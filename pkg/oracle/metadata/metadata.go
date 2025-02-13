package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const metadataURL = "http://169.254.169.254/opc/v2/"

type InstanceMetadata struct {
	AvailabilityDomain string `json:"availabilityDomain"` // TODO maybe it's ociAdName?
	Shape              string `json:"shape"`
	InstanceID         string `json:"id"`
}

type ShapeConfig struct {
	MaxVnicAttachments int `json:"maxVnicAttachments"`
}

func fetchMetadata[T any](ctx context.Context, path string) (T, error) {
	var result T

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	url := fmt.Sprintf("%s/%s", metadataURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}
	req.Header.Add("Authorization", "Bearer Oracle")

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("metadata service returned status code %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, fmt.Errorf("failed to decode metadata response: %w", err)
	}

	return result, nil
}

func GetShapeConfig(ctx context.Context) (ShapeConfig, error) {
	return fetchMetadata[ShapeConfig](ctx, "/instance/shapeConfig")
}

func GetInstanceMetadata(ctx context.Context) (InstanceMetadata, error) {
	return fetchMetadata[InstanceMetadata](ctx, "/instance")
}
