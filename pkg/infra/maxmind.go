package infra

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

type maxmindGeo struct {
	db *maxminddb.Reader
}

type maxmindRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	Location struct {
		TimeZone       string   `maxminddb:"time_zone"`
		Latitude       *float64 `maxminddb:"latitude"`
		Longitude      *float64 `maxminddb:"longitude"`
		AccuracyRadius uint16   `maxminddb:"accuracy_radius"`
	} `maxminddb:"location"`
}

// OpenGeoIP opens a MaxMind DB file and returns a GeoIP lookup.
// A missing file returns the open error.
func OpenGeoIP(path string) (GeoIP, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &maxmindGeo{db: db}, nil
}

func (g *maxmindGeo) Lookup(ip net.IP) (Place, error) {
	var record maxmindRecord
	if err := g.db.Lookup(ip, &record); err != nil {
		return Place{}, err
	}
	place := Place{
		City:        record.City.Names["en"],
		PostalCode:  record.Postal.Code,
		Country:     record.Country.Names["en"],
		CountryCode: record.Country.ISOCode,
		TimeZone:    record.Location.TimeZone,
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
		AccuracyKM:  int(record.Location.AccuracyRadius),
	}
	if len(record.Subdivisions) > 0 {
		place.Region = record.Subdivisions[0].Names["en"]
	}
	return place, nil
}
