package keyring

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewOPDesktopKeyring(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         Config
		expectError error
	}{
		{
			name: "valid configuration",
			cfg: Config{
				OPTimeout:            5 * time.Second,
				OPVaultID:            "vaultID",
				OPDesktopAccountName: "accountName",
			},
			expectError: nil,
		},
		{
			name: "missing timeout",
			cfg: Config{
				OPVaultID:            "vaultID",
				OPDesktopAccountName: "accountName",
			},
			expectError: OPDesktopErrTimeout,
		},
		{
			name: "missing vault ID",
			cfg: Config{
				OPTimeout:            5 * time.Second,
				OPDesktopAccountName: "accountName",
			},
			expectError: OPErrVaultID,
		},
		{
			name: "missing desktop account name",
			cfg: Config{
				OPTimeout: 5 * time.Second,
				OPVaultID: "vaultID",
			},
			expectError: OPDesktopErrAccountName,
		},
		{
			name:        "missing all",
			cfg:         Config{},
			expectError: errors.Join(OPDesktopErrTimeout, OPErrVaultID, OPDesktopErrAccountName),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyring, err := NewOPDesktopKeyring(&tc.cfg)
			if tc.expectError != nil {
				assert.ErrorContains(t, err, tc.expectError.Error())
				assert.Nil(t, keyring)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, keyring)
				assert.Equal(t, tc.cfg.OPTimeout, keyring.Timeout)
				assert.Equal(t, tc.cfg.OPVaultID, keyring.VaultID)
				assert.Equal(t, tc.cfg.OPDesktopAccountName, keyring.DesktopAccountName)
			}
		})
	}
}
