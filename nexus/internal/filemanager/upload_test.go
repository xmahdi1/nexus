package filemanager

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type uploadZeros struct{}

func (uploadZeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

type countedUpload struct {
	io.Reader
	read int64
}

func (r *countedUpload) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += int64(n)
	return n, err
}

func TestUploadBoundsMultipartBeforeParsingAndSSH(t *testing.T) {
	const requestLimit = maxTransferBytes + (1 << 20)
	for _, knownLength := range []bool{true, false} {
		t.Run(map[bool]string{true: "content_length", false: "streamed"}[knownLength], func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			body := &countedUpload{Reader: io.MultiReader(
				strings.NewReader("--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"),
				io.LimitReader(uploadZeros{}, requestLimit+(4<<20)),
				strings.NewReader("\r\n--fixture--\r\n"),
			)}
			request := httptest.NewRequest(http.MethodPost, "/", body)
			request.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
			request.ContentLength = -1
			if knownLength {
				request.ContentLength = requestLimit + (4 << 20)
			}
			response := httptest.NewRecorder()
			// A nil DB/pool makes an accidental SSH attempt fail this test.
			(&Handler{}).Upload(response, request)
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversized multipart returned %d", response.Code)
			}
			limit := requestLimit + 1
			if knownLength {
				limit = 0
			}
			if body.read > limit {
				t.Errorf("read %d bytes before rejecting; limit %d", body.read, limit)
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("multipart temporary files remain: %d entries, %v", len(entries), err)
			}
		})
	}
}
