// Package adws - Type conversion between ADWS and LDAP formats
package adws

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	soap "github.com/Macmod/go-adws/soap"
)

// convertADWSValue converts an ADWSValue to a plain string using the ADWS LdapSyntax tag.
// Most syntaxes are already marshalled as strings by ADWS; OctetString is the exception
// and is returned as a lowercase hex string derived from the pre-decoded RawValue bytes.
func convertADWSValue(val *soap.ADWSValue) (string, error) {
	switch val.LdapSyntax {
	case "UnicodeString", "IA5String", "PrintableString", "NumericString",
		"DNString", "GeneralizedTimeString", "BooleanString":
		return val.Value, nil

	case "IntegerString":
		// Validate it's a valid integer
		if _, err := strconv.ParseInt(val.Value, 10, 64); err != nil {
			return "", fmt.Errorf("invalid IntegerString: %s", val.Value)
		}
		return val.Value, nil

	case "SidString":
		// Already in S-1-5-... format
		return val.Value, nil

	case "OctetString":
		// OctetString is ambiguous - check attribute name for special handling
		// For now, return hex-encoded bytes
		if len(val.RawValue) > 0 {
			return hex.EncodeToString(val.RawValue), nil
		}
		return val.Value, nil

	default:
		// Unknown syntax - return as-is
		return val.Value, nil
	}
}

// ConvertSIDBytes converts a binary SID to S-1-5-... format.
//
// SID format:
//   [0]    Revision (always 1)
//   [1]    SubAuthorityCount (number of SubAuthorities)
//   [2:8]  IdentifierAuthority (6 bytes, big-endian)
//   [8:]   SubAuthorities (4 bytes each, little-endian)
func ConvertSIDBytes(sidBytes []byte) (string, error) {
	if len(sidBytes) < 8 {
		return "", fmt.Errorf("SID too short: %d bytes", len(sidBytes))
	}

	revision := sidBytes[0]
	subAuthorityCount := sidBytes[1]

	// IdentifierAuthority occupies 6 bytes in big-endian order.
	authority := uint64(0)
	for i := 0; i < 6; i++ {
		authority = (authority << 8) | uint64(sidBytes[2+i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	// Read SubAuthorities (4 bytes each, little-endian)
	offset := 8
	for i := 0; i < int(subAuthorityCount); i++ {
		if offset+4 > len(sidBytes) {
			return "", fmt.Errorf("SID truncated at SubAuthority %d", i)
		}
		subAuth := binary.LittleEndian.Uint32(sidBytes[offset : offset+4])
		sid += fmt.Sprintf("-%d", subAuth)
		offset += 4
	}

	return sid, nil
}

// ConvertGUIDBytes converts a binary GUID to standard GUID format.
//
// GUID format (mixed-endian):
//   [0:4]   Data1 (little-endian)
//   [4:6]   Data2 (little-endian)
//   [6:8]   Data3 (little-endian)
//   [8:16]  Data4 (big-endian, 8 bytes)
//
// Output format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
func ConvertGUIDBytes(guidBytes []byte) (string, error) {
	if len(guidBytes) != 16 {
		return "", fmt.Errorf("GUID must be 16 bytes, got %d", len(guidBytes))
	}

	data1 := binary.LittleEndian.Uint32(guidBytes[0:4])
	data2 := binary.LittleEndian.Uint16(guidBytes[4:6])
	data3 := binary.LittleEndian.Uint16(guidBytes[6:8])
	data4 := guidBytes[8:16] // Big-endian, 8 bytes

	// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data1, data2, data3,
		data4[0], data4[1],
		data4[2], data4[3], data4[4], data4[5], data4[6], data4[7],
	), nil
}

// DetectAttributeType attempts to detect the binary attribute type by name.
//
// This is needed because OctetString is ambiguous - it can be SID, GUID,
// or other binary data.
func DetectAttributeType(attrName string) string {
	// Heuristic mapping for common AD binary attribute names.

	lower := strings.ToLower(attrName)

	switch {
	case lower == "objectsid", lower == "sidhistory":
		return "sid"
	case lower == "objectguid", lower == "schemaIDGUID", lower == "attributeSecurityGUID",
		lower == "mS-DS-ConsistencyGuid":
		return "guid"
	case lower == "useraccountcontrol", lower == "systemflags", lower == "searchflags",
		lower == "grouptype":
		return "int32"
	case lower == "usercertificate", lower == "thumbnailphoto", lower == "jpeegphoto":
		return "binary"
	default:
		return "unknown"
	}
}
