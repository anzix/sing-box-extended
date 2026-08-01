package link

import (
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	E "github.com/sagernet/sing/common/exceptions"
)

func parseNaiveLink(link string) (option.Outbound, error) {
	var forceQUIC bool

	switch {
	case strings.HasPrefix(link, "naive+https://"):
		link = "https://" + strings.TrimPrefix(link, "naive+https://")

	case strings.HasPrefix(link, "naive+quic://"):
		link = "https://" + strings.TrimPrefix(link, "naive+quic://")
		forceQUIC = true

	case strings.HasPrefix(link, "naive://"):
		link = "https://" + strings.TrimPrefix(link, "naive://")

	default:
		return option.Outbound{}, E.New("invalid naive link")
	}

	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}

	if linkURL.User == nil {
		return option.Outbound{}, E.New("missing credentials")
	}

	username := linkURL.User.Username()
	if username == "" {
		return option.Outbound{}, E.New("missing username")
	}

	password, ok := linkURL.User.Password()
	if !ok {
		return option.Outbound{}, E.New("missing password")
	}

	options := option.NaiveOutboundOptions{
		Username: username,
		Password: password,
	}

	options.Server = linkURL.Hostname()

	if port := linkURL.Port(); port != "" {
		options.ServerPort = common.StringToType[uint16](port)
	} else {
		options.ServerPort = 443
	}

	tlsOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
	}

	tlsOptions.ServerName = linkURL.Hostname()

	if forceQUIC {
		options.QUIC = true
	}

	for key, values := range linkURL.Query() {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		switch key {
		case "sni":
			tlsOptions.ServerName = value
		case "insecure", "allowInsecure":
			if value == "1" || strings.EqualFold(value, "true") {
				tlsOptions.Insecure = true
			}
		case "tls_certificate":
			tlsOptions.Certificate = []string{
				strings.ReplaceAll(value, ",", "\n"),
			}
		case "concurrency":
			options.InsecureConcurrency = common.StringToType[int](value)
		case "uot":
			if value == "1" || strings.EqualFold(value, "true") {
				options.UDPOverTCP = &option.UDPOverTCPOptions{}
			}
		case "quic":
			if value == "1" || strings.EqualFold(value, "true") {
				options.QUIC = true
			}
		case "quic_congestion_control":
			options.QUICCongestionControl = value
		}
	}

	options.TLS = &tlsOptions

	return option.Outbound{
		Type:    C.TypeNaive,
		Tag:     linkURL.Fragment,
		Options: &options,
	}, nil
}
