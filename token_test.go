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

import "testing"

func TestJWT_NewHeader(t *testing.T) {
	hs256 := HmacSha256("super-secret-key")
	hs256Header := hs256.NewHeader()
	if hs256Header.Typ != "JWT" {
		t.Errorf("jwt.TestJWT_NewHeader, hs256: invalid Typ: %s != %s", "JWT", hs256Header.Typ)
	}
	if hs256Header.Alg != "HS256" {
		t.Errorf("jwt.TestJWT_NewHeader, hs256: invalid Alg: %s != %s", "HS256", hs256Header.Alg)
	}

	hs512 := HmacSha512("super-secret-key")
	hs512Header := hs512.NewHeader()
	if hs512Header.Typ != "JWT" {
		t.Errorf("jwt.TestJWT_NewHeader, hs512: invalid Typ: %s != %s", "JWT", hs512Header.Typ)
	}
	if hs512Header.Alg != "HS512" {
		t.Errorf("jwt.TestJWT_NewHeader, hs512: invalid Alg: %s != %s", "HS512", hs512Header.Alg)
	}

	hs384 := HmacSha384("super-secret-key")
	hs384Header := hs384.NewHeader()
	if hs384Header.Typ != "JWT" {
		t.Errorf("jwt.TestJWT_NewHeader, hs384: invalid Typ: %s != %s", "JWT", hs384Header.Typ)
	}
	if hs384Header.Alg != "HS384" {
		t.Errorf("jwt.TestJWT_NewHeader, hs384: invalid Alg: %s != %s", "HS512", hs384Header.Alg)
	}
}

var TestJWT_sum_Data = []struct {
	hs256 []struct{
		data     []byte
		expected []byte
	}
	hs512 []struct{
		data     []byte
		expected []byte
	}
	hs384 []struct{
		data     []byte
		expected []byte
	}
}{
	{
		hs256: []struct {
			data     []byte
			expected []byte
		}{
			{
				data: []byte("Sodales molestie vel tempus. Dignissim egestas. Scelerisque nascetur bibendum ad morbi donec arcu orci. Tortor proin amet tortor mauris mi."),
				expected: []byte{83, 111, 100, 97, 108, 101, 115, 32, 109, 111, 108, 101, 115, 116, 105, 101, 32, 118, 101, 108, 32, 116, 101, 109, 112, 117, 115, 46, 32, 68, 105, 103, 110, 105, 115, 115, 105, 109, 32, 101, 103, 101, 115, 116, 97, 115, 46, 32, 83, 99, 101, 108, 101, 114, 105, 115, 113, 117, 101, 32, 110, 97, 115, 99, 101, 116, 117, 114, 32, 98, 105, 98, 101, 110, 100, 117, 109, 32, 97, 100, 32, 109, 111, 114, 98, 105, 32, 100, 111, 110, 101, 99, 32, 97, 114, 99, 117, 32, 111, 114, 99, 105, 46, 32, 84, 111, 114, 116, 111, 114, 32, 112, 114, 111, 105, 110, 32, 97, 109, 101, 116, 32, 116, 111, 114, 116, 111, 114, 32, 109, 97, 117, 114, 105, 115, 32, 109, 105, 46, 79, 180, 82, 90, 118, 48, 186, 67, 67, 146, 59, 197, 159, 211, 138, 66, 250, 227, 69, 79, 1, 194, 24, 107, 53, 226, 18, 190, 137, 165, 188, 107},
			},
			{
				data: []byte("Nisi sociis diam varius vulputate quam lacus viverra velit, ridiculus ac euismod curae; cubilia facilisis tellus dictum eleifend lorem ullamcorper."),
				expected: []byte{78, 105, 115, 105, 32, 115, 111, 99, 105, 105, 115, 32, 100, 105, 97, 109, 32, 118, 97, 114, 105, 117, 115, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 113, 117, 97, 109, 32, 108, 97, 99, 117, 115, 32, 118, 105, 118, 101, 114, 114, 97, 32, 118, 101, 108, 105, 116, 44, 32, 114, 105, 100, 105, 99, 117, 108, 117, 115, 32, 97, 99, 32, 101, 117, 105, 115, 109, 111, 100, 32, 99, 117, 114, 97, 101, 59, 32, 99, 117, 98, 105, 108, 105, 97, 32, 102, 97, 99, 105, 108, 105, 115, 105, 115, 32, 116, 101, 108, 108, 117, 115, 32, 100, 105, 99, 116, 117, 109, 32, 101, 108, 101, 105, 102, 101, 110, 100, 32, 108, 111, 114, 101, 109, 32, 117, 108, 108, 97, 109, 99, 111, 114, 112, 101, 114, 46, 79, 180, 82, 90, 118, 48, 186, 67, 67, 146, 59, 197, 159, 211, 138, 66, 250, 227, 69, 79, 1, 194, 24, 107, 53, 226, 18, 190, 137, 165, 188, 107},
			},
			{
				data: []byte("Volutpat condimentum per integer enim ac leo diam cras penatibus aliquam aenean odio. Faucibus. Ullamcorper aliquam. Litora praesent aliquet aptent."),
				expected: []byte{86, 111, 108, 117, 116, 112, 97, 116, 32, 99, 111, 110, 100, 105, 109, 101, 110, 116, 117, 109, 32, 112, 101, 114, 32, 105, 110, 116, 101, 103, 101, 114, 32, 101, 110, 105, 109, 32, 97, 99, 32, 108, 101, 111, 32, 100, 105, 97, 109, 32, 99, 114, 97, 115, 32, 112, 101, 110, 97, 116, 105, 98, 117, 115, 32, 97, 108, 105, 113, 117, 97, 109, 32, 97, 101, 110, 101, 97, 110, 32, 111, 100, 105, 111, 46, 32, 70, 97, 117, 99, 105, 98, 117, 115, 46, 32, 85, 108, 108, 97, 109, 99, 111, 114, 112, 101, 114, 32, 97, 108, 105, 113, 117, 97, 109, 46, 32, 76, 105, 116, 111, 114, 97, 32, 112, 114, 97, 101, 115, 101, 110, 116, 32, 97, 108, 105, 113, 117, 101, 116, 32, 97, 112, 116, 101, 110, 116, 46, 79, 180, 82, 90, 118, 48, 186, 67, 67, 146, 59, 197, 159, 211, 138, 66, 250, 227, 69, 79, 1, 194, 24, 107, 53, 226, 18, 190, 137, 165, 188, 107},
			},
			{
				data: []byte("Urna dis nisl vulputate aenean mauris, tempor cubilia ultrices pellentesque imperdiet Suscipit. Augue ridiculus sollicitudin nam, augue. Fames hendrerit natoque."),
				expected: []byte{85, 114, 110, 97, 32, 100, 105, 115, 32, 110, 105, 115, 108, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 97, 101, 110, 101, 97, 110, 32, 109, 97, 117, 114, 105, 115, 44, 32, 116, 101, 109, 112, 111, 114, 32, 99, 117, 98, 105, 108, 105, 97, 32, 117, 108, 116, 114, 105, 99, 101, 115, 32, 112, 101, 108, 108, 101, 110, 116, 101, 115, 113, 117, 101, 32, 105, 109, 112, 101, 114, 100, 105, 101, 116, 32, 83, 117, 115, 99, 105, 112, 105, 116, 46, 32, 65, 117, 103, 117, 101, 32, 114, 105, 100, 105, 99, 117, 108, 117, 115, 32, 115, 111, 108, 108, 105, 99, 105, 116, 117, 100, 105, 110, 32, 110, 97, 109, 44, 32, 97, 117, 103, 117, 101, 46, 32, 70, 97, 109, 101, 115, 32, 104, 101, 110, 100, 114, 101, 114, 105, 116, 32, 110, 97, 116, 111, 113, 117, 101, 46, 79, 180, 82, 90, 118, 48, 186, 67, 67, 146, 59, 197, 159, 211, 138, 66, 250, 227, 69, 79, 1, 194, 24, 107, 53, 226, 18, 190, 137, 165, 188, 107},
			},
			{
				data: []byte("Natoque porttitor sapien vulputate dolor mattis elementum iaculis inceptos in. Consectetuer class urna non egestas. Pellentesque posuere senectus iaculis hymenaeos."),
				expected: []byte{78, 97, 116, 111, 113, 117, 101, 32, 112, 111, 114, 116, 116, 105, 116, 111, 114, 32, 115, 97, 112, 105, 101, 110, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 100, 111, 108, 111, 114, 32, 109, 97, 116, 116, 105, 115, 32, 101, 108, 101, 109, 101, 110, 116, 117, 109, 32, 105, 97, 99, 117, 108, 105, 115, 32, 105, 110, 99, 101, 112, 116, 111, 115, 32, 105, 110, 46, 32, 67, 111, 110, 115, 101, 99, 116, 101, 116, 117, 101, 114, 32, 99, 108, 97, 115, 115, 32, 117, 114, 110, 97, 32, 110, 111, 110, 32, 101, 103, 101, 115, 116, 97, 115, 46, 32, 80, 101, 108, 108, 101, 110, 116, 101, 115, 113, 117, 101, 32, 112, 111, 115, 117, 101, 114, 101, 32, 115, 101, 110, 101, 99, 116, 117, 115, 32, 105, 97, 99, 117, 108, 105, 115, 32, 104, 121, 109, 101, 110, 97, 101, 111, 115, 46, 79, 180, 82, 90, 118, 48, 186, 67, 67, 146, 59, 197, 159, 211, 138, 66, 250, 227, 69, 79, 1, 194, 24, 107, 53, 226, 18, 190, 137, 165, 188, 107},
			},
		},
		hs512: []struct {
			data     []byte
			expected []byte
		}{
			{
				data: []byte("Sodales molestie vel tempus. Dignissim egestas. Scelerisque nascetur bibendum ad morbi donec arcu orci. Tortor proin amet tortor mauris mi."),
				expected: []byte{83, 111, 100, 97, 108, 101, 115, 32, 109, 111, 108, 101, 115, 116, 105, 101, 32, 118, 101, 108, 32, 116, 101, 109, 112, 117, 115, 46, 32, 68, 105, 103, 110, 105, 115, 115, 105, 109, 32, 101, 103, 101, 115, 116, 97, 115, 46, 32, 83, 99, 101, 108, 101, 114, 105, 115, 113, 117, 101, 32, 110, 97, 115, 99, 101, 116, 117, 114, 32, 98, 105, 98, 101, 110, 100, 117, 109, 32, 97, 100, 32, 109, 111, 114, 98, 105, 32, 100, 111, 110, 101, 99, 32, 97, 114, 99, 117, 32, 111, 114, 99, 105, 46, 32, 84, 111, 114, 116, 111, 114, 32, 112, 114, 111, 105, 110, 32, 97, 109, 101, 116, 32, 116, 111, 114, 116, 111, 114, 32, 109, 97, 117, 114, 105, 115, 32, 109, 105, 46, 174, 224, 4, 207, 124, 104, 164, 198, 20, 76, 106, 94, 17, 194, 163, 38, 1, 183, 25, 224, 174, 183, 58, 204, 156, 70, 211, 154, 144, 102, 192, 89, 0, 11, 7, 46, 49, 225, 50, 156, 59, 228, 83, 190, 153, 171, 195, 198, 208, 183, 146, 225, 186, 125, 49, 11, 252, 87, 198, 113, 252, 108, 78, 176},
			},
			{
				data: []byte("Nisi sociis diam varius vulputate quam lacus viverra velit, ridiculus ac euismod curae; cubilia facilisis tellus dictum eleifend lorem ullamcorper."),
				expected: []byte{78, 105, 115, 105, 32, 115, 111, 99, 105, 105, 115, 32, 100, 105, 97, 109, 32, 118, 97, 114, 105, 117, 115, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 113, 117, 97, 109, 32, 108, 97, 99, 117, 115, 32, 118, 105, 118, 101, 114, 114, 97, 32, 118, 101, 108, 105, 116, 44, 32, 114, 105, 100, 105, 99, 117, 108, 117, 115, 32, 97, 99, 32, 101, 117, 105, 115, 109, 111, 100, 32, 99, 117, 114, 97, 101, 59, 32, 99, 117, 98, 105, 108, 105, 97, 32, 102, 97, 99, 105, 108, 105, 115, 105, 115, 32, 116, 101, 108, 108, 117, 115, 32, 100, 105, 99, 116, 117, 109, 32, 101, 108, 101, 105, 102, 101, 110, 100, 32, 108, 111, 114, 101, 109, 32, 117, 108, 108, 97, 109, 99, 111, 114, 112, 101, 114, 46, 174, 224, 4, 207, 124, 104, 164, 198, 20, 76, 106, 94, 17, 194, 163, 38, 1, 183, 25, 224, 174, 183, 58, 204, 156, 70, 211, 154, 144, 102, 192, 89, 0, 11, 7, 46, 49, 225, 50, 156, 59, 228, 83, 190, 153, 171, 195, 198, 208, 183, 146, 225, 186, 125, 49, 11, 252, 87, 198, 113, 252, 108, 78, 176},
			},
			{
				data: []byte("Volutpat condimentum per integer enim ac leo diam cras penatibus aliquam aenean odio. Faucibus. Ullamcorper aliquam. Litora praesent aliquet aptent."),
				expected: []byte{86, 111, 108, 117, 116, 112, 97, 116, 32, 99, 111, 110, 100, 105, 109, 101, 110, 116, 117, 109, 32, 112, 101, 114, 32, 105, 110, 116, 101, 103, 101, 114, 32, 101, 110, 105, 109, 32, 97, 99, 32, 108, 101, 111, 32, 100, 105, 97, 109, 32, 99, 114, 97, 115, 32, 112, 101, 110, 97, 116, 105, 98, 117, 115, 32, 97, 108, 105, 113, 117, 97, 109, 32, 97, 101, 110, 101, 97, 110, 32, 111, 100, 105, 111, 46, 32, 70, 97, 117, 99, 105, 98, 117, 115, 46, 32, 85, 108, 108, 97, 109, 99, 111, 114, 112, 101, 114, 32, 97, 108, 105, 113, 117, 97, 109, 46, 32, 76, 105, 116, 111, 114, 97, 32, 112, 114, 97, 101, 115, 101, 110, 116, 32, 97, 108, 105, 113, 117, 101, 116, 32, 97, 112, 116, 101, 110, 116, 46, 174, 224, 4, 207, 124, 104, 164, 198, 20, 76, 106, 94, 17, 194, 163, 38, 1, 183, 25, 224, 174, 183, 58, 204, 156, 70, 211, 154, 144, 102, 192, 89, 0, 11, 7, 46, 49, 225, 50, 156, 59, 228, 83, 190, 153, 171, 195, 198, 208, 183, 146, 225, 186, 125, 49, 11, 252, 87, 198, 113, 252, 108, 78, 176},
			},
			{
				data: []byte("Urna dis nisl vulputate aenean mauris, tempor cubilia ultrices pellentesque imperdiet Suscipit. Augue ridiculus sollicitudin nam, augue. Fames hendrerit natoque."),
				expected: []byte{85, 114, 110, 97, 32, 100, 105, 115, 32, 110, 105, 115, 108, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 97, 101, 110, 101, 97, 110, 32, 109, 97, 117, 114, 105, 115, 44, 32, 116, 101, 109, 112, 111, 114, 32, 99, 117, 98, 105, 108, 105, 97, 32, 117, 108, 116, 114, 105, 99, 101, 115, 32, 112, 101, 108, 108, 101, 110, 116, 101, 115, 113, 117, 101, 32, 105, 109, 112, 101, 114, 100, 105, 101, 116, 32, 83, 117, 115, 99, 105, 112, 105, 116, 46, 32, 65, 117, 103, 117, 101, 32, 114, 105, 100, 105, 99, 117, 108, 117, 115, 32, 115, 111, 108, 108, 105, 99, 105, 116, 117, 100, 105, 110, 32, 110, 97, 109, 44, 32, 97, 117, 103, 117, 101, 46, 32, 70, 97, 109, 101, 115, 32, 104, 101, 110, 100, 114, 101, 114, 105, 116, 32, 110, 97, 116, 111, 113, 117, 101, 46, 174, 224, 4, 207, 124, 104, 164, 198, 20, 76, 106, 94, 17, 194, 163, 38, 1, 183, 25, 224, 174, 183, 58, 204, 156, 70, 211, 154, 144, 102, 192, 89, 0, 11, 7, 46, 49, 225, 50, 156, 59, 228, 83, 190, 153, 171, 195, 198, 208, 183, 146, 225, 186, 125, 49, 11, 252, 87, 198, 113, 252, 108, 78, 176},
			},
			{
				data: []byte("Natoque porttitor sapien vulputate dolor mattis elementum iaculis inceptos in. Consectetuer class urna non egestas. Pellentesque posuere senectus iaculis hymenaeos."),
				expected: []byte{78, 97, 116, 111, 113, 117, 101, 32, 112, 111, 114, 116, 116, 105, 116, 111, 114, 32, 115, 97, 112, 105, 101, 110, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 100, 111, 108, 111, 114, 32, 109, 97, 116, 116, 105, 115, 32, 101, 108, 101, 109, 101, 110, 116, 117, 109, 32, 105, 97, 99, 117, 108, 105, 115, 32, 105, 110, 99, 101, 112, 116, 111, 115, 32, 105, 110, 46, 32, 67, 111, 110, 115, 101, 99, 116, 101, 116, 117, 101, 114, 32, 99, 108, 97, 115, 115, 32, 117, 114, 110, 97, 32, 110, 111, 110, 32, 101, 103, 101, 115, 116, 97, 115, 46, 32, 80, 101, 108, 108, 101, 110, 116, 101, 115, 113, 117, 101, 32, 112, 111, 115, 117, 101, 114, 101, 32, 115, 101, 110, 101, 99, 116, 117, 115, 32, 105, 97, 99, 117, 108, 105, 115, 32, 104, 121, 109, 101, 110, 97, 101, 111, 115, 46, 174, 224, 4, 207, 124, 104, 164, 198, 20, 76, 106, 94, 17, 194, 163, 38, 1, 183, 25, 224, 174, 183, 58, 204, 156, 70, 211, 154, 144, 102, 192, 89, 0, 11, 7, 46, 49, 225, 50, 156, 59, 228, 83, 190, 153, 171, 195, 198, 208, 183, 146, 225, 186, 125, 49, 11, 252, 87, 198, 113, 252, 108, 78, 176},
			},
		},
		hs384: []struct {
			data     []byte
			expected []byte
		}{
			{
				data: []byte("Sodales molestie vel tempus. Dignissim egestas. Scelerisque nascetur bibendum ad morbi donec arcu orci. Tortor proin amet tortor mauris mi."),
				expected: []byte{83, 111, 100, 97, 108, 101, 115, 32, 109, 111, 108, 101, 115, 116, 105, 101, 32, 118, 101, 108, 32, 116, 101, 109, 112, 117, 115, 46, 32, 68, 105, 103, 110, 105, 115, 115, 105, 109, 32, 101, 103, 101, 115, 116, 97, 115, 46, 32, 83, 99, 101, 108, 101, 114, 105, 115, 113, 117, 101, 32, 110, 97, 115, 99, 101, 116, 117, 114, 32, 98, 105, 98, 101, 110, 100, 117, 109, 32, 97, 100, 32, 109, 111, 114, 98, 105, 32, 100, 111, 110, 101, 99, 32, 97, 114, 99, 117, 32, 111, 114, 99, 105, 46, 32, 84, 111, 114, 116, 111, 114, 32, 112, 114, 111, 105, 110, 32, 97, 109, 101, 116, 32, 116, 111, 114, 116, 111, 114, 32, 109, 97, 117, 114, 105, 115, 32, 109, 105, 46, 255, 14, 230, 151, 208, 226, 125, 56, 127, 255, 150, 158, 59, 131, 134, 198, 30, 255, 123, 181, 170, 184, 13, 120, 134, 13, 66, 254, 70, 106, 127, 40, 199, 178, 8, 105, 81, 2, 47, 157, 72, 187, 235, 172, 123, 119, 251, 46},
			},
			{
				data: []byte("Nisi sociis diam varius vulputate quam lacus viverra velit, ridiculus ac euismod curae; cubilia facilisis tellus dictum eleifend lorem ullamcorper."),
				expected: []byte{78, 105, 115, 105, 32, 115, 111, 99, 105, 105, 115, 32, 100, 105, 97, 109, 32, 118, 97, 114, 105, 117, 115, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 113, 117, 97, 109, 32, 108, 97, 99, 117, 115, 32, 118, 105, 118, 101, 114, 114, 97, 32, 118, 101, 108, 105, 116, 44, 32, 114, 105, 100, 105, 99, 117, 108, 117, 115, 32, 97, 99, 32, 101, 117, 105, 115, 109, 111, 100, 32, 99, 117, 114, 97, 101, 59, 32, 99, 117, 98, 105, 108, 105, 97, 32, 102, 97, 99, 105, 108, 105, 115, 105, 115, 32, 116, 101, 108, 108, 117, 115, 32, 100, 105, 99, 116, 117, 109, 32, 101, 108, 101, 105, 102, 101, 110, 100, 32, 108, 111, 114, 101, 109, 32, 117, 108, 108, 97, 109, 99, 111, 114, 112, 101, 114, 46, 255, 14, 230, 151, 208, 226, 125, 56, 127, 255, 150, 158, 59, 131, 134, 198, 30, 255, 123, 181, 170, 184, 13, 120, 134, 13, 66, 254, 70, 106, 127, 40, 199, 178, 8, 105, 81, 2, 47, 157, 72, 187, 235, 172, 123, 119, 251, 46},
			},
			{
				data: []byte("Volutpat condimentum per integer enim ac leo diam cras penatibus aliquam aenean odio. Faucibus. Ullamcorper aliquam. Litora praesent aliquet aptent."),
				expected: []byte{86, 111, 108, 117, 116, 112, 97, 116, 32, 99, 111, 110, 100, 105, 109, 101, 110, 116, 117, 109, 32, 112, 101, 114, 32, 105, 110, 116, 101, 103, 101, 114, 32, 101, 110, 105, 109, 32, 97, 99, 32, 108, 101, 111, 32, 100, 105, 97, 109, 32, 99, 114, 97, 115, 32, 112, 101, 110, 97, 116, 105, 98, 117, 115, 32, 97, 108, 105, 113, 117, 97, 109, 32, 97, 101, 110, 101, 97, 110, 32, 111, 100, 105, 111, 46, 32, 70, 97, 117, 99, 105, 98, 117, 115, 46, 32, 85, 108, 108, 97, 109, 99, 111, 114, 112, 101, 114, 32, 97, 108, 105, 113, 117, 97, 109, 46, 32, 76, 105, 116, 111, 114, 97, 32, 112, 114, 97, 101, 115, 101, 110, 116, 32, 97, 108, 105, 113, 117, 101, 116, 32, 97, 112, 116, 101, 110, 116, 46, 255, 14, 230, 151, 208, 226, 125, 56, 127, 255, 150, 158, 59, 131, 134, 198, 30, 255, 123, 181, 170, 184, 13, 120, 134, 13, 66, 254, 70, 106, 127, 40, 199, 178, 8, 105, 81, 2, 47, 157, 72, 187, 235, 172, 123, 119, 251, 46},
			},
			{
				data: []byte("Urna dis nisl vulputate aenean mauris, tempor cubilia ultrices pellentesque imperdiet Suscipit. Augue ridiculus sollicitudin nam, augue. Fames hendrerit natoque."),
				expected: []byte{85, 114, 110, 97, 32, 100, 105, 115, 32, 110, 105, 115, 108, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 97, 101, 110, 101, 97, 110, 32, 109, 97, 117, 114, 105, 115, 44, 32, 116, 101, 109, 112, 111, 114, 32, 99, 117, 98, 105, 108, 105, 97, 32, 117, 108, 116, 114, 105, 99, 101, 115, 32, 112, 101, 108, 108, 101, 110, 116, 101, 115, 113, 117, 101, 32, 105, 109, 112, 101, 114, 100, 105, 101, 116, 32, 83, 117, 115, 99, 105, 112, 105, 116, 46, 32, 65, 117, 103, 117, 101, 32, 114, 105, 100, 105, 99, 117, 108, 117, 115, 32, 115, 111, 108, 108, 105, 99, 105, 116, 117, 100, 105, 110, 32, 110, 97, 109, 44, 32, 97, 117, 103, 117, 101, 46, 32, 70, 97, 109, 101, 115, 32, 104, 101, 110, 100, 114, 101, 114, 105, 116, 32, 110, 97, 116, 111, 113, 117, 101, 46, 255, 14, 230, 151, 208, 226, 125, 56, 127, 255, 150, 158, 59, 131, 134, 198, 30, 255, 123, 181, 170, 184, 13, 120, 134, 13, 66, 254, 70, 106, 127, 40, 199, 178, 8, 105, 81, 2, 47, 157, 72, 187, 235, 172, 123, 119, 251, 46},
			},
			{
				data: []byte("Natoque porttitor sapien vulputate dolor mattis elementum iaculis inceptos in. Consectetuer class urna non egestas. Pellentesque posuere senectus iaculis hymenaeos."),
				expected: []byte{78, 97, 116, 111, 113, 117, 101, 32, 112, 111, 114, 116, 116, 105, 116, 111, 114, 32, 115, 97, 112, 105, 101, 110, 32, 118, 117, 108, 112, 117, 116, 97, 116, 101, 32, 100, 111, 108, 111, 114, 32, 109, 97, 116, 116, 105, 115, 32, 101, 108, 101, 109, 101, 110, 116, 117, 109, 32, 105, 97, 99, 117, 108, 105, 115, 32, 105, 110, 99, 101, 112, 116, 111, 115, 32, 105, 110, 46, 32, 67, 111, 110, 115, 101, 99, 116, 101, 116, 117, 101, 114, 32, 99, 108, 97, 115, 115, 32, 117, 114, 110, 97, 32, 110, 111, 110, 32, 101, 103, 101, 115, 116, 97, 115, 46, 32, 80, 101, 108, 108, 101, 110, 116, 101, 115, 113, 117, 101, 32, 112, 111, 115, 117, 101, 114, 101, 32, 115, 101, 110, 101, 99, 116, 117, 115, 32, 105, 97, 99, 117, 108, 105, 115, 32, 104, 121, 109, 101, 110, 97, 101, 111, 115, 46, 255, 14, 230, 151, 208, 226, 125, 56, 127, 255, 150, 158, 59, 131, 134, 198, 30, 255, 123, 181, 170, 184, 13, 120, 134, 13, 66, 254, 70, 106, 127, 40, 199, 178, 8, 105, 81, 2, 47, 157, 72, 187, 235, 172, 123, 119, 251, 46},
			},
		},
	},
}

func TestJWT_sum(t *testing.T) {
	hs256 := HmacSha256("super-secret-key")
	for _, data := range TestJWT_sum_Data {
		for _, d := range data.hs256 {
			actual := hs256.sum(d.data)
			if len(actual) != len(d.expected) {
				t.Errorf("jwt.TestJWT_sum, hs256: invalid sum len: %d != %d", len(actual), len(d.expected))
			}
			for i, b := range actual {
				if b != d.expected[i] {
					t.Errorf("jwt.TestJWT_sum, hs256: invalid sum[%d]: %d != %d", i, b, d.expected[i])
				}
			}
		}
	}

	hs512 := HmacSha512("super-secret-key")
	for _, data := range TestJWT_sum_Data {
		for _, d := range data.hs512 {
			actual := hs512.sum(d.data)
			if len(actual) != len(d.expected) {
				t.Errorf("jwt.TestJWT_sum, hs512: invalid sum len: %d != %d", len(actual), len(d.expected))
			}
			for i, b := range actual {
				if b != d.expected[i] {
					t.Errorf("jwt.TestJWT_sum, hs512: invalid sum[%d]: %d != %d", i, b, d.expected[i])
				}
			}
		}
	}

	hs384 := HmacSha384("super-secret-key")
	for _, data := range TestJWT_sum_Data {
		for _, d := range data.hs384 {
			actual := hs384.sum(d.data)
			if len(actual) != len(d.expected) {
				t.Errorf("jwt.TestJWT_sum, hs384: invalid sum len: %d != %d", len(actual), len(d.expected))
			}
			for i, b := range actual {
				if b != d.expected[i] {
					t.Errorf("jwt.TestJWT_sum, hs384: invalid sum[%d]: %d != %d", i, b, d.expected[i])
				}
			}
		}
	}
}

var TestJWT_write_Data = []struct {
	data     []byte
	expected int
}{
	{
		data: []byte("Sodales molestie vel tempus. Dignissim egestas. Scelerisque nascetur bibendum ad morbi donec arcu orci. Tortor proin amet tortor mauris mi."),
		expected: 139,
	},
	{
		data: []byte("Nisi sociis diam varius vulputate quam lacus viverra velit, ridiculus ac euismod curae; cubilia facilisis tellus dictum eleifend lorem ullamcorper."),
		expected: 147,
	},
	{
		data: []byte("Volutpat condimentum per integer enim ac leo diam cras penatibus aliquam aenean odio. Faucibus. Ullamcorper aliquam. Litora praesent aliquet aptent."),
		expected: 148,
	},
	{
		data: []byte("Urna dis nisl vulputate aenean mauris, tempor cubilia ultrices pellentesque imperdiet Suscipit. Augue ridiculus sollicitudin nam, augue. Fames hendrerit natoque."),
		expected: 161,
	},
	{
		data: []byte("Natoque porttitor sapien vulputate dolor mattis elementum iaculis inceptos in. Consectetuer class urna non egestas. Pellentesque posuere senectus iaculis hymenaeos."),
		expected: 164,
	},
}

func TestJWT_write(t *testing.T) {
	hs256 := HmacSha256("super-secret-key")
	for _, data := range TestJWT_write_Data {
		actual, _ := hs256.write(data.data)
		if actual != data.expected {
			t.Errorf("jwt.TestJWT_write: invalid write result: %d != %d", actual, data.expected)
		}
	}
}
