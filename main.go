package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/julienschmidt/httprouter"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/sget"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"gopkg.in/yaml.v2"
)

type HorismosConfig struct {
	// TODO: Figure out if keys should be given in a request or if Horismos should have it's own trust store
	BaseKeyPath string `yaml:"base_key_path"`
	// This should be a map of reference extensions to what they map to. For POC "image" is a special case that refers to the image itself
	// TODO: Expand on this and probably make a struct or enum for the extensions
	KeyMap map[string]string `yaml:"key_map"`

	Port string `yaml:"port"`
}

type VerifyType int32

const (
	VerifyUnsupported VerifyType = iota
	VerifySignature
	VerifyAttestation
)

type VerifyRequest struct {
	// NOTE: This doesn't have to be an actual OCI/Container image and can just refer to any object in the repo.
	Image string
}

type VerifyResponse struct {
	Verified            bool   `json:"verified"`
	VerificationMessage string `json:"verification_message"`
	Payload             []byte `json:"payload"`
}

func Verify(config HorismosConfig, verifyType VerifyType) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if verifyType == VerifyUnsupported {
			http.Error(w, "Unsupported Verification Type", http.StatusInternalServerError)
			return
		}

		var body VerifyRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := context.TODO()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: Support using more than the image key for attestations
		verifier, err := cli.LoadPublicKey(ctx, filepath.Join(config.BaseKeyPath, config.KeyMap["image"]))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ref, err := name.ParseReference(body.Image)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ro := &cli.RegistryOpts{
			AllowInsecure: false,
		}

		var co *cosign.CheckOpts
		switch verifyType {
		case VerifySignature:
			co = &cosign.CheckOpts{
				RootCerts:          fulcio.GetRoots(),
				SigVerifier:        verifier,
				RegistryClientOpts: ro.GetRegistryClientOpts(ctx),
			}
			break
		case VerifyAttestation:
			sigRepo, err := cli.TargetRepositoryForImage(ref)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			co = &cosign.CheckOpts{
				RootCerts:            fulcio.GetRoots(),
				RegistryClientOpts:   ro.GetRegistryClientOpts(ctx),
				ClaimVerifier:        cosign.IntotoSubjectClaimVerifier,
				SigTagSuffixOverride: cosign.AttestationTagSuffix,
				SigVerifier:          dsse.WrapVerifier(verifier),
				SignatureRepo:        sigRepo,
				VerifyBundle:         false,
			}
			break
		default:
			http.Error(w, "This verify type is not supported yet", http.StatusInternalServerError)
		}

		var resp VerifyResponse
		if verified, err := cosign.Verify(ctx, ref, co); err != nil {
			resp = VerifyResponse{
				Verified:            false,
				VerificationMessage: err.Error(),
			}
		} else {
			resp = VerifyResponse{
				Verified:            true,
				VerificationMessage: fmt.Sprintf("valid signatures found for an image: %s", body.Image),
				Payload:             verified[0].Payload,
			}
		}

		respAsByte, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(respAsByte)
	}
}

type DownloadType int32

const (
	DownloadUnsupported DownloadType = iota
	DownloadBlob
)

type DownloadRequest struct {
	// NOTE: This refers to the blob
	Image     string
	Extension string
}

type DownloadResponse struct {
	Verified            bool   `json:"verified"`
	VerificationMessage string `json:"verification_message"`
	Payload             []byte `json:"payload"`
}

func Download(config HorismosConfig, downloadType DownloadType) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if downloadType == DownloadUnsupported {
			http.Error(w, "Unsupported Download Type", http.StatusInternalServerError)
			return
		}

		var body DownloadRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Printf("%+v\n", body.Image)
		tag := strings.SplitN(body.Image, ":", 2)[1]
		extension := strings.SplitN(tag, ".", 2)[1]
		keyPath := path.Join(config.BaseKeyPath, config.KeyMap[extension])
		buf := new(bytes.Buffer)
		ctx := context.TODO()
		sgetter := sget.New(body.Image, keyPath, buf)
		err = sgetter.Do(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		// TODO: Support more than just application/json
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf.Bytes())
	}
}

func NewHorismosConfig(path string) (*HorismosConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)

	var horismosConfig HorismosConfig
	if err := decoder.Decode(&horismosConfig); err != nil {
		return nil, err
	}

	return &horismosConfig, nil
}

func main() {
	horismosConfigPath := os.Getenv("HORISMOS_CONFIG")
	if horismosConfigPath == "" {
		horismosConfigPath = "/tmp/keys/horismos.yaml"
	}
	config, err := NewHorismosConfig(horismosConfigPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("%v\n", config)
	router := httprouter.New()
	router.POST("/verify/signature", Verify(*config, VerifySignature))
	router.POST("/verify/attestation", Verify(*config, VerifyAttestation))
	router.POST("/download/blob", Download(*config, DownloadBlob))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", config.Port), router))
}
