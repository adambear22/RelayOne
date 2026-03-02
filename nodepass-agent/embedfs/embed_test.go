package embedfs

import "testing"

func TestEmbedPathFor(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		goarch  string
		want    string
		wantErr bool
	}{
		{name: "linux amd64", goos: "linux", goarch: "amd64", want: "nodepass_linux_amd64"},
		{name: "linux arm64", goos: "linux", goarch: "arm64", want: "nodepass_linux_arm64"},
		{name: "linux armv7", goos: "linux", goarch: "armv7", want: "nodepass_linux_armv7"},
		{name: "darwin amd64", goos: "darwin", goarch: "amd64", want: "nodepass_darwin_amd64"},
		{name: "darwin arm64", goos: "darwin", goarch: "arm64", want: "nodepass_darwin_arm64"},
		{name: "unsupported", goos: "windows", goarch: "amd64", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EmbedPathFor(tc.goos, tc.goarch)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("EmbedPathFor returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("EmbedPathFor = %q, want %q", got, tc.want)
			}
		})
	}
}
