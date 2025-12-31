package keyring

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewOPSrvAccountKeyring(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         Config
		expectError error
	}{
		{
			name: "valid configuration",
			cfg: Config{
				OPTimeout: 5 * time.Second,
				OPVaultID: "vaultID",
			},
			expectError: nil,
		},
		{
			name: "missing timeout",
			cfg: Config{
				OPVaultID: "vaultID",
			},
			expectError: OPSrvAccountErrTimeout,
		},
		{
			name: "missing vault ID",
			cfg: Config{
				OPTimeout: 5 * time.Second,
			},
			expectError: OPErrVaultID,
		},
		{
			name:        "missing all",
			cfg:         Config{},
			expectError: errors.Join(OPSrvAccountErrTimeout, OPErrVaultID),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyring, err := NewOPSrvAccountKeyring(&tc.cfg)
			if tc.expectError != nil {
				assert.ErrorContains(t, err, tc.expectError.Error())
				assert.Nil(t, keyring)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, keyring)
				assert.Equal(t, tc.cfg.OPTimeout, keyring.Timeout)
				assert.Equal(t, tc.cfg.OPVaultID, keyring.VaultID)
			}
		})
	}
}
