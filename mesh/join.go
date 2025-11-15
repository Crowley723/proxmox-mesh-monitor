package mesh

//func Join(joinAddr, joinToken, configPath, certDir string) error {
//	cert, csr, err := generateCSR()
//	if err != nil {
//		return fmt.Errorf("failed to generate CSR: %w", err)
//	}
//
//	signedCert, err := requestCertSigning(bootstrapNode, bootstrapToken, csr)
//	if err != nil {
//		return fmt.Errorf("failed to get cert signed: %w", err)
//	}
//
//	cfg, err := fetchConfig(bootstrapNode, signedCert)
//	if err != nil {
//		return fmt.Errorf("failed to fetch config: %w", err)
//	}
//
//	if err := writeConfigFile(cfg); err != nil {
//		return fmt.Errorf("failed to write config file: %w", err)
//	}
//
//	if err := writeCerts(cert, signedCert); err != nil {
//		return fmt.Errorf("failed to write certificates: %w", err)
//	}
//
//	return nil
//}
