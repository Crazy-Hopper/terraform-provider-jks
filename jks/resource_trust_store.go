package jks

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	"time"
)

func resourceTrustStore() *schema.Resource {
	return &schema.Resource{
		Description:   "JKS trust store generated from one or more PEM encoded certificates.",
		CreateContext: resourceTrustStoreCreate,
		ReadContext:   resourceTrustStoreRead,
		DeleteContext: resourceTrustStoreDelete,
		Schema: map[string]*schema.Schema{
			"certificates": {
				Description: "CA certificates or chains to include in generated trust store; in PEM format.",
				Type:        schema.TypeList,
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				MinItems: 1,
				ForceNew: true,
			},
			"password": {
				Description: "Password to secure trust store. Defaults to empty string.",
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				ForceNew:    true,
			},
			"timestamp": {
				Description: "Timestamp of trust store creation in RFC3339 format.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"jks": {
				Description: "JKS trust store data; base64 encoded.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceTrustStoreCreate(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	ks := keystore.New()

	ts, err := time.Parse(time.RFC3339, d.Get("timestamp").(string))
	if err != nil {
		ts = time.Now().Truncate(time.Second).UTC()
		d.Set("timestamp", ts.Format(time.RFC3339))
	}

	chainCertsInterfaces := d.Get("certificates").([]interface{})
	if len(chainCertsInterfaces) == 0 {
		return diag.Errorf("empty certificates")
	}
	chainCerts := []string{}
	for _, ci := range chainCertsInterfaces {
		chainCerts = append(chainCerts, ci.(string))
	}

	keystoreCerts, err := transformPemCertsToKeystoreCert(chainCerts)
	if err != nil {
		return diag.Errorf("cant transform pem chainCerts to keystore chainCerts: %s", err.Error())
	}
	for i, keystoreCert := range keystoreCerts {
		err := ks.SetTrustedCertificateEntry(
			fmt.Sprintf("%d", i),
			keystore.TrustedCertificateEntry{
				CreationTime: ts,
				Certificate:  keystoreCert,
			},
		)
		if err != nil {
			return diag.Errorf("cant add cert %d to truststore: %s", err.Error())
		}
	}

	var jksBuffer bytes.Buffer
	jksWriter := bufio.NewWriter(&jksBuffer)

	err = ks.Store(jksWriter, []byte(d.Get("password").(string)))
	if err != nil {
		return diag.Errorf("failed to generate JKS: %s", err.Error())
	}

	err = jksWriter.Flush()
	if err != nil {
		return diag.Errorf("failed to flush JKS: %v", err)
	}

	jksData := base64.StdEncoding.EncodeToString(jksBuffer.Bytes())

	idHash := crypto.SHA1.New()
	idHash.Write([]byte(jksData))

	id := hex.EncodeToString(idHash.Sum([]byte{}))
	d.SetId(id)

	if err = d.Set("jks", jksData); err != nil {
		return diag.Errorf("failed to save JKS: %v", err)
	}

	return nil
}

func resourceTrustStoreRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceTrustStoreCreate(ctx, d, m)
}

func resourceTrustStoreDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	d.SetId("")

	return diags
}
