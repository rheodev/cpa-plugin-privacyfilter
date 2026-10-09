//go:build !betterleaks

package detect

func newSecrets(cfg SecretsConfig) (Detector, error) {
	_ = cfg
	return nil, ErrSecretsUnavailable
}
