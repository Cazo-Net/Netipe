package parser

import (
	"fmt"
	"io"
	"sort"

	"github.com/netpipe/netpipe/internal/model"
)

type DeviceParser interface {
	Name() string
	SupportedTypes() []model.DeviceType
	Detect(data []byte) bool
	DetectScore(data []byte) int
	Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error)
}

type parserEntry struct {
	name   string
	parser DeviceParser
}

var registry = map[string]parserEntry{}

func Register(name string, p DeviceParser) {
	registry[name] = parserEntry{name: name, parser: p}
}

func Get(name string) (DeviceParser, error) {
	entry, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown parser: %s", name)
	}
	return entry.parser, nil
}

func All() map[string]DeviceParser {
	result := make(map[string]DeviceParser, len(registry))
	for _, v := range registry {
		result[v.name] = v.parser
	}
	return result
}

type scoredMatch struct {
	parser DeviceParser
	score  int
	typ    model.DeviceType
}

func DetectDeviceType(data []byte) (model.DeviceType, DeviceParser) {
	var matches []scoredMatch
	for _, entry := range registry {
		if entry.parser.Detect(data) {
			score := entry.parser.DetectScore(data)
			types := entry.parser.SupportedTypes()
			typ := model.DeviceUnknown
			if len(types) > 0 {
				typ = types[0]
			}
			matches = append(matches, scoredMatch{parser: entry.parser, score: score, typ: typ})
		}
	}
	if len(matches) == 0 {
		return model.DeviceUnknown, nil
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].score > matches[j].score
	})
	return matches[0].typ, matches[0].parser
}

func ParserForType(dt model.DeviceType) (DeviceParser, error) {
	for _, entry := range registry {
		for _, t := range entry.parser.SupportedTypes() {
			if t == dt {
				return entry.parser, nil
			}
		}
	}
	return nil, fmt.Errorf("no parser for device type: %s", dt)
}
