package tigasdk

import "github.com/absurdlab/tiga-go-sdk/oidc"

// Discovery returns a new copy of the underlying internal oidc.Discovery.
func (s *SDK) Discovery() *oidc.Discovery {
	return s.discovery.Clone()
}
