package config

import "time"

type Config struct {
	Keys          Keys    `yaml:"keys"`
	Listen        Listen  `yaml:"listen"`
	Timeout       Timeout `yaml:"timeout"`
	GeoIP         GeoIP   `yaml:"geoIP"`
	Verbose       bool    `yaml:"verbose"`
	ReplayHistory int     `yaml:"replayHistory"`
}

type Keys struct {
	Path string `yaml:"path"`
}

type Listen struct {
	Metrics string `yaml:"metrics"`
}

type GeoIP struct {
	Countries string `yaml:"countries"`
	ASN       string `yaml:"ASN"`
}

type Timeout struct {
	NAT     Duration `yaml:"nat"`
	TCPRead Duration `yaml:"tcpRead"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var (
		s   string
		err error
	)

	if err = unmarshal(&s); err != nil {
		return err
	}

	if d.Duration, err = time.ParseDuration(s); err != nil {
		return err
	}

	return nil
}
