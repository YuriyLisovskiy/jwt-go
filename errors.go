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

import "errors"

var (
	// Claims errors.
	ErrClaimDoesNotExist = errors.New("claim does not exist")
	ErrClaimNotAString   = errors.New("claim is not a string")
	ErrClaimNotInt8      = errors.New("claim is not an int8")
	ErrClaimNotUint8     = errors.New("claim is not an uint8")
	ErrClaimNotInt16     = errors.New("claim is not an int16")
	ErrClaimNotUint16    = errors.New("claim is not an uint16")
	ErrClaimNotInt32     = errors.New("claim is not an int32")
	ErrClaimNotUint32    = errors.New("claim is not an uint32")
	ErrClaimNotInt       = errors.New("claim is not an int")
	ErrClaimNotUint      = errors.New("claim is not an uint")
	ErrClaimNotInt64     = errors.New("claim is not an int64")
	ErrClaimNotUint64    = errors.New("claim is not an uint64")
	ErrClaimNotFloat32   = errors.New("claim is not float32")
	ErrClaimNotFloat64   = errors.New("claim is not float64")
	ErrClaimNotBool      = errors.New("claim is not bool")

	// Token's errors.
	ErrTokenIsMalformed               = errors.New("malformed token")
	ErrTokenHasExpired                = errors.New("token has expired")
	ErrTokenInvalidSignature          = errors.New("invalid signature")
	ErrTokenUnableToSign              = errors.New("unable to sign token")
	ErrTokenNotValid                  = errors.New("token isn't valid yet")
	ErrTokenUnableToMarshallHeader    = errors.New("unable to marshal header")
	ErrTokenUnableToMarshallPayload   = errors.New("unable to marshal payload")
	ErrTokenUnableToDecodeB64Payload  = errors.New("unable to decode base64 payload")
	ErrTokenUnableToUnmarshallPayload = errors.New("unable to unmarshal payload json")
)
