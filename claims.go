// Copyright (c) 2018 Yuriy Lisovskiy
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package jwt

import "time"

// Claims represents a list of claims of a JWT token.
//
//  Registered Claim Names (source: https://tools.ietf.org/html/rfc7519#section-4.1)
//
//	- "iss" (Issuer) Claim - string
//
//      The "iss" (issuer) claim identifies the principal that issued the
//      JWT.  The processing of this claim is generally application specific.
//      The "iss" value is a case-sensitive string containing a StringOrURI
//      value.  Use of this claim is OPTIONAL.
//
//
//	- "sub" (Subject) Claim - string
//
//      The "sub" (subject) claim identifies the principal that is the
//      subject of the JWT.  The claims in a JWT are normally statements
//      about the subject.  The subject value MUST either be scoped to be
//      locally unique in the context of the issuer or be globally unique.
//      The processing of this claim is generally application specific.  The
//      sub" value is a case-sensitive string containing a StringOrURI
//      value.  Use of this claim is OPTIONAL.
//
//
//	- "aud" (Audience) Claim - string
//
//      The "aud" (audience) claim identifies the recipients that the JWT is
//      intended for.  Each principal intended to process the JWT MUST
//      identify itself with a value in the audience claim.  If the principal
//      processing the claim does not identify itself with a value in the
//      "aud" claim when this claim is present, then the JWT MUST be
//      rejected.  In the general case, the "aud" value is an array of case-
//      sensitive strings, each containing a StringOrURI value.  In the
//      special case when the JWT has one audience, the "aud" value MAY be a
//      single case-sensitive string containing a StringOrURI value.  The
//      interpretation of audience values is generally application specific.
//      Use of this claim is OPTIONAL.
//
//
//	- "exp" (Expiration Time) Claim - time
//
//      The "exp" (expiration time) claim identifies the expiration time on
//      or after which the JWT MUST NOT be accepted for processing.  The
//      processing of the "exp" claim requires that the current date/time
//      MUST be before the expiration date/time listed in the "exp" claim.
//      Implementers MAY provide for some small leeway, usually no more than
//      a few minutes, to account for clock skew.  Its value MUST be a number
//      containing a NumericDate value.  Use of this claim is OPTIONAL.
//
//
//	- "nbf" (Not Before) Claim - time
//
//      The "nbf" (not before) claim identifies the time before which the JWT
//      MUST NOT be accepted for processing.  The processing of the "nbf"
//      claim requires that the current date/time MUST be after or equal to
//      the not-before date/time listed in the "nbf" claim.  Implementers MAY
//      provide for some small leeway, usually no more than a few minutes, to
//      account for clock skew.  Its value MUST be a number containing a
//      NumericDate value.  Use of this claim is OPTIONAL.
//
//
//	- "iat" (Issued At) Claim - time
//
//      The "iat" (issued at) claim identifies the time at which the JWT was
//      issued.  This claim can be used to determine the age of the JWT.  Its
//      value MUST be a number containing a NumericDate value.  Use of this
//      claim is OPTIONAL.
//
//
//	- "jti" (JWT ID) Claim - string
//
//      The "jti" (JWT ID) claim provides a unique identifier for the JWT.
//      The identifier value MUST be assigned in a manner that ensures that
//      there is a negligible probability that the same value will be
//      accidentally assigned to a different data object; if the application
//      uses multiple issuers, collisions MUST be prevented among values
//      produced by different issuers as well.  The "jti" claim can be used
//      to prevent the JWT from being replayed.  The "jti" value is a case-
//      sensitive string.  Use of this claim is OPTIONAL.

type Claims struct {
	claims map[string]interface{}
}

// NewClaims returns a new map representing the claims with "iat" claim value.
func NewClaims() *Claims {
	newClaims := make(map[string]interface{})
	claims := &Claims{
		claims: newClaims,
	}
	claims.SetTime("iat", time.Now())
	return claims
}

// Contains returns if the claims map has given key.
func (c *Claims) Contains(key string) bool {
	_, ok := c.claims[key]
	return ok
}

// Set sets the claim in string form.
func (c *Claims) Set(key string, value interface{}) {
	c.claims[key] = value
}

// SetTime sets the claim given to the specified time.
func (c *Claims) SetTime(key string, value time.Time) {
	c.Set(key, value.Unix())
}

// Get returns the claim in string form and returns an error if the specified claim doesn't exist.
func (c Claims) Get(key string) (interface{}, error) {
	result, ok := c.claims[key]
	if !ok {
		return "", ErrClaimDoesNotExist
	}
	return result, nil
}

// GetString attempts to return a claim as string.
func (c *Claims) GetString(key string) (string, error) {
	raw, err := c.Get(key)
	if err != nil {
		return "", err
	}
	str, ok := raw.(string)
	if !ok {
		return "", ErrClaimNotAString
	}
	return str, nil
}

// GetFloat64 attempts to return a claim as float64.
func (c *Claims) GetFloat64(key string) (float64, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(float64)
	if !ok {
		return 0, ErrClaimNotFloat64
	}
	return val, nil
}

// GetFloat32 attempts to return a claim as float32.
func (c *Claims) GetFloat32(key string) (float32, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(float32)
	if !ok {
		return 0, ErrClaimNotFloat32
	}
	return val, nil
}

// GetInt8 attempts to return a claim as int8.
func (c *Claims) GetInt8(key string) (int8, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(int8)
	if !ok {
		return 0, ErrClaimNotInt8
	}
	return val, nil
}

// GetUint8 attempts to return a claim as uint8.
func (c *Claims) GetUint8(key string) (uint8, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(uint8)
	if !ok {
		return 0, ErrClaimNotUint8
	}
	return val, nil
}

// GetInt16 attempts to return a claim as int16.
func (c *Claims) GetInt16(key string) (int16, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(int16)
	if !ok {
		return 0, ErrClaimNotInt16
	}
	return val, nil
}

// GetUint16 attempts to return a claim as uint16.
func (c *Claims) GetUint16(key string) (uint16, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(uint16)
	if !ok {
		return 0, ErrClaimNotUint16
	}
	return val, nil
}

// GetInt attempts to return a claim as int.
func (c *Claims) GetInt(key string) (int, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(int)
	if !ok {
		return 0, ErrClaimNotInt
	}
	return val, nil
}

// GetUint attempts to return a claim as uint.
func (c *Claims) GetUint(key string) (uint, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(uint)
	if !ok {
		return 0, ErrClaimNotUint
	}
	return val, nil
}

// GetInt32 attempts to return a claim as int32.
func (c *Claims) GetInt32(key string) (int32, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(int32)
	if !ok {
		return 0, ErrClaimNotInt32
	}
	return val, nil
}

// GetUint32 attempts to return a claim as uint32.
func (c *Claims) GetUint32(key string) (uint32, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(uint32)
	if !ok {
		return 0, ErrClaimNotUint32
	}
	return val, nil
}

// GetInt64 attempts to return a claim as int64.
func (c *Claims) GetInt64(key string) (int64, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(int64)
	if !ok {
		return 0, ErrClaimNotInt64
	}
	return val, nil
}

// GetUint64 attempts to return a claim as uint64.
func (c *Claims) GetUint64(key string) (uint64, error) {
	raw, err := c.Get(key)
	if err != nil {
		return 0, err
	}
	val, ok := raw.(uint64)
	if !ok {
		return 0, ErrClaimNotUint64
	}
	return val, nil
}

// GetBool attempts to return a claim as bool.
func (c *Claims) GetBool(key string) (bool, error) {
	raw, err := c.Get(key)
	if err != nil {
		return false, err
	}
	val, ok := raw.(bool)
	if !ok {
		return false, ErrClaimNotBool
	}
	return val, nil
}

// GetTime attempts to return a claim as a time.
func (c *Claims) GetTime(key string) (time.Time, error) {
	val, err := c.GetInt64(key)
	return time.Unix(val, 0), err
}
