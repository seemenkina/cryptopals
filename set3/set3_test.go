package set3

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func TestAESStruct_PaddingOracleAttack(t *testing.T) {
	msg := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	aKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(aKey)

	as := AESStruct{key: aKey}

	//c := rand2.Intn(9)
	for c := 0; c < len(msg); c++ {
		raw, _ := base64.StdEncoding.DecodeString(msg[c])
		cip, iv := as.Encrypt(raw)
		ms := as.PaddingOracleAttack(cip, iv)
		require.EqualValues(t, ms, raw)
	}

}

func TestCTRAes(t *testing.T) {
	msg := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	raw, _ := base64.StdEncoding.DecodeString(msg)
	input := []struct {
		input    []byte
		expected []byte
		key      []byte
		nonce    int
	}{
		{raw, []byte("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "),
			[]byte("YELLOW SUBMARINE"), 0},
	}

	for _, tt := range input {
		tt := tt
		t.Run("", func(t *testing.T) {
			cipher, err := CTRAES(tt.key, tt.input, tt.nonce)
			require.NoError(t, err)
			require.EqualValues(t, cipher, tt.expected)
		})
	}
}

func TestFixedNonceCTRAttack(t *testing.T) {
	var err error
	msg := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}

	aKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(aKey)
	nonce := 0
	as := AESStruct{key: aKey}
	ciphers := make([][]byte, len(msg))
	for i := 0; i < len(msg); i++ {
		raw, _ := base64.StdEncoding.DecodeString(msg[i])
		ciphers[i], err = CTRAES(as.key, raw, nonce)
		require.NoError(t, err)
	}

	as.FixedNonceCTRAttackSubstitution(ciphers, nonce)
}

func TestAESStruct_FixedNonceCTRAttackStatistically(t *testing.T) {
	var err error
	msg := []string{
		"SSdtIHJhdGVkICJSIi4uLnRoaXMgaXMgYSB3YXJuaW5nLCB5YSBiZXR0ZXIgdm9pZCAvIFBvZXRzIGFyZSBwYXJhbm9pZCwgREoncyBELXN0cm95ZWQ=",
		"Q3V6IEkgY2FtZSBiYWNrIHRvIGF0dGFjayBvdGhlcnMgaW4gc3BpdGUtIC8gU3RyaWtlIGxpa2UgbGlnaHRuaW4nLCBJdCdzIHF1aXRlIGZyaWdodGVuaW4nIQ==",
		"QnV0IGRvbid0IGJlIGFmcmFpZCBpbiB0aGUgZGFyaywgaW4gYSBwYXJrIC8gTm90IGEgc2NyZWFtIG9yIGEgY3J5LCBvciBhIGJhcmssIG1vcmUgbGlrZSBhIHNwYXJrOw==",
		"WWEgdHJlbWJsZSBsaWtlIGEgYWxjb2hvbGljLCBtdXNjbGVzIHRpZ2h0ZW4gdXAgLyBXaGF0J3MgdGhhdCwgbGlnaHRlbiB1cCEgWW91IHNlZSBhIHNpZ2h0IGJ1dA==",
		"U3VkZGVubHkgeW91IGZlZWwgbGlrZSB5b3VyIGluIGEgaG9ycm9yIGZsaWNrIC8gWW91IGdyYWIgeW91ciBoZWFydCB0aGVuIHdpc2ggZm9yIHRvbW9ycm93IHF1aWNrIQ==",
		"TXVzaWMncyB0aGUgY2x1ZSwgd2hlbiBJIGNvbWUgeW91ciB3YXJuZWQgLyBBcG9jYWx5cHNlIE5vdywgd2hlbiBJJ20gZG9uZSwgeWEgZ29uZSE=",
		"SGF2ZW4ndCB5b3UgZXZlciBoZWFyZCBvZiBhIE1DLW11cmRlcmVyPyAvIFRoaXMgaXMgdGhlIGRlYXRoIHBlbmFsdHksYW5kIEknbSBzZXJ2aW4nIGE=",
		"RGVhdGggd2lzaCwgc28gY29tZSBvbiwgc3RlcCB0byB0aGlzIC8gSHlzdGVyaWNhbCBpZGVhIGZvciBhIGx5cmljYWwgcHJvZmVzc2lvbmlzdCE=",
		"RnJpZGF5IHRoZSB0aGlydGVlbnRoLCB3YWxraW5nIGRvd24gRWxtIFN0cmVldCAvIFlvdSBjb21lIGluIG15IHJlYWxtIHlhIGdldCBiZWF0IQ==",
		"VGhpcyBpcyBvZmYgbGltaXRzLCBzbyB5b3VyIHZpc2lvbnMgYXJlIGJsdXJyeSAvIEFsbCB5YSBzZWUgaXMgdGhlIG1ldGVycyBhdCBhIHZvbHVtZQ==",
		"VGVycm9yIGluIHRoZSBzdHlsZXMsIG5ldmVyIGVycm9yLWZpbGVzIC8gSW5kZWVkIEknbSBrbm93bi15b3VyIGV4aWxlZCE=",
		"Rm9yIHRob3NlIHRoYXQgb3Bwb3NlIHRvIGJlIGxldmVsIG9yIG5leHQgdG8gdGhpcyAvIEkgYWluJ3QgYSBkZXZpbCBhbmQgdGhpcyBhaW4ndCB0aGUgRXhvcmNpc3Qh",
		"V29yc2UgdGhhbiBhIG5pZ2h0bWFyZSwgeW91IGRvbid0IGhhdmUgdG8gc2xlZXAgYSB3aW5rIC8gVGhlIHBhaW4ncyBhIG1pZ3JhaW5lIGV2ZXJ5IHRpbWUgeWEgdGhpbms=",
		"Rmxhc2hiYWNrcyBpbnRlcmZlcmUsIHlhIHN0YXJ0IHRvIGhlYXI6IC8gVGhlIFItQS1LLUktTSBpbiB5b3VyIGVhcjs=",
		"VGhlbiB0aGUgYmVhdCBpcyBoeXN0ZXJpY2FsIC8gVGhhdCBtYWtlcyBFcmljIGdvIGdldCBhIGF4IGFuZCBjaG9wcyB0aGUgd2Fjaw==",
		"U29vbiB0aGUgbHlyaWNhbCBmb3JtYXQgaXMgc3VwZXJpb3IgLyBGYWNlcyBvZiBkZWF0aCByZW1haW4=",
		"TUMncyBkZWNheWluZywgY3V6IHRoZXkgbmV2ZXIgc3RheWVkIC8gVGhlIHNjZW5lIG9mIGEgY3JpbWUgZXZlcnkgbmlnaHQgYXQgdGhlIHNob3c=",
		"VGhlIGZpZW5kIG9mIGEgcmh5bWUgb24gdGhlIG1pYyB0aGF0IHlvdSBrbm93IC8gSXQncyBvbmx5IG9uZSBjYXBhYmxlLCBicmVha3MtdGhlIHVuYnJlYWthYmxl",
		"TWVsb2RpZXMtdW5tYWthYmxlLCBwYXR0ZXJuLXVuZXNjYXBhYmxlIC8gQSBob3JuIGlmIHdhbnQgdGhlIHN0eWxlIEkgcG9zc2Vz",
		"SSBibGVzcyB0aGUgY2hpbGQsIHRoZSBlYXJ0aCwgdGhlIGdvZHMgYW5kIGJvbWIgdGhlIHJlc3QgLyBGb3IgdGhvc2UgdGhhdCBlbnZ5IGEgTUMgaXQgY2FuIGJl",
		"SGF6YXJkb3VzIHRvIHlvdXIgaGVhbHRoIHNvIGJlIGZyaWVuZGx5IC8gQSBtYXR0ZXIgb2YgbGlmZSBhbmQgZGVhdGgsIGp1c3QgbGlrZSBhIGV0Y2gtYS1za2V0Y2g=",
		"U2hha2UgJ3RpbGwgeW91ciBjbGVhciwgbWFrZSBpdCBkaXNhcHBlYXIsIG1ha2UgdGhlIG5leHQgLyBBZnRlciB0aGUgY2VyZW1vbnksIGxldCB0aGUgcmh5bWUgcmVzdCBpbiBwZWFjZQ==",
		"SWYgbm90LCBteSBzb3VsJ2xsIHJlbGVhc2UhIC8gVGhlIHNjZW5lIGlzIHJlY3JlYXRlZCwgcmVpbmNhcm5hdGVkLCB1cGRhdGVkLCBJJ20gZ2xhZCB5b3UgbWFkZSBpdA==",
		"Q3V6IHlvdXIgYWJvdXQgdG8gc2VlIGEgZGlzYXN0cm91cyBzaWdodCAvIEEgcGVyZm9ybWFuY2UgbmV2ZXIgYWdhaW4gcGVyZm9ybWVkIG9uIGEgbWljOg==",
		"THlyaWNzIG9mIGZ1cnkhIEEgZmVhcmlmaWVkIGZyZWVzdHlsZSEgLyBUaGUgIlIiIGlzIGluIHRoZSBob3VzZS10b28gbXVjaCB0ZW5zaW9uIQ==",
		"TWFrZSBzdXJlIHRoZSBzeXN0ZW0ncyBsb3VkIHdoZW4gSSBtZW50aW9uIC8gUGhyYXNlcyB0aGF0J3MgZmVhcnNvbWU=",
		"WW91IHdhbnQgdG8gaGVhciBzb21lIHNvdW5kcyB0aGF0IG5vdCBvbmx5IHBvdW5kcyBidXQgcGxlYXNlIHlvdXIgZWFyZHJ1bXM7IC8gSSBzaXQgYmFjayBhbmQgb2JzZXJ2ZSB0aGUgd2hvbGUgc2NlbmVyeQ==",
		"VGhlbiBub25jaGFsYW50bHkgdGVsbCB5b3Ugd2hhdCBpdCBtZWFuIHRvIG1lIC8gU3RyaWN0bHkgYnVzaW5lc3MgSSdtIHF1aWNrbHkgaW4gdGhpcyBtb29k",
		"QW5kIEkgZG9uJ3QgY2FyZSBpZiB0aGUgd2hvbGUgY3Jvd2QncyBhIHdpdG5lc3MhIC8gSSdtIGEgdGVhciB5b3UgYXBhcnQgYnV0IEknbSBhIHNwYXJlIHlvdSBhIGhlYXJ0",
		"UHJvZ3JhbSBpbnRvIHRoZSBzcGVlZCBvZiB0aGUgcmh5bWUsIHByZXBhcmUgdG8gc3RhcnQgLyBSaHl0aG0ncyBvdXQgb2YgdGhlIHJhZGl1cywgaW5zYW5lIGFzIHRoZSBjcmF6aWVzdA==",
		"TXVzaWNhbCBtYWRuZXNzIE1DIGV2ZXIgbWFkZSwgc2VlIGl0J3MgLyBOb3cgYW4gZW1lcmdlbmN5LCBvcGVuLWhlYXJ0IHN1cmdlcnk=",
		"T3BlbiB5b3VyIG1pbmQsIHlvdSB3aWxsIGZpbmQgZXZlcnkgd29yZCdsbCBiZSAvIEZ1cmllciB0aGFuIGV2ZXIsIEkgcmVtYWluIHRoZSBmdXJ0dXJl",
		"QmF0dGxlJ3MgdGVtcHRpbmcuLi53aGF0ZXZlciBzdWl0cyB5YSEgLyBGb3Igd29yZHMgdGhlIHNlbnRlbmNlLCB0aGVyZSdzIG5vIHJlc2VtYmxhbmNl",
		"WW91IHRoaW5rIHlvdSdyZSBydWZmZXIsIHRoZW4gc3VmZmVyIHRoZSBjb25zZXF1ZW5jZXMhIC8gSSdtIG5ldmVyIGR5aW5nLXRlcnJpZnlpbmcgcmVzdWx0cw==",
		"SSB3YWtlIHlhIHdpdGggaHVuZHJlZHMgb2YgdGhvdXNhbmRzIG9mIHZvbHRzIC8gTWljLXRvLW1vdXRoIHJlc3VzY2l0YXRpb24sIHJoeXRobSB3aXRoIHJhZGlhdGlvbg==",
		"Tm92b2NhaW4gZWFzZSB0aGUgcGFpbiBpdCBtaWdodCBzYXZlIGhpbSAvIElmIG5vdCwgRXJpYyBCLidzIHRoZSBqdWRnZSwgdGhlIGNyb3dkJ3MgdGhlIGp1cnk=",
		"WW8gUmFraW0sIHdoYXQncyB1cD8gLyBZbywgSSdtIGRvaW5nIHRoZSBrbm93bGVkZ2UsIEUuLCBtYW4gSSdtIHRyeWluZyB0byBnZXQgcGFpZCBpbiBmdWxs",
		"V2VsbCwgY2hlY2sgdGhpcyBvdXQsIHNpbmNlIE5vcmJ5IFdhbHRlcnMgaXMgb3VyIGFnZW5jeSwgcmlnaHQ/IC8gVHJ1ZQ==",
		"S2FyYSBMZXdpcyBpcyBvdXIgYWdlbnQsIHdvcmQgdXAgLyBaYWtpYSBhbmQgNHRoIGFuZCBCcm9hZHdheSBpcyBvdXIgcmVjb3JkIGNvbXBhbnksIGluZGVlZA==",
		"T2theSwgc28gd2hvIHdlIHJvbGxpbicgd2l0aCB0aGVuPyBXZSByb2xsaW4nIHdpdGggUnVzaCAvIE9mIFJ1c2h0b3duIE1hbmFnZW1lbnQ=",
		"Q2hlY2sgdGhpcyBvdXQsIHNpbmNlIHdlIHRhbGtpbmcgb3ZlciAvIFRoaXMgZGVmIGJlYXQgcmlnaHQgaGVyZSB0aGF0IEkgcHV0IHRvZ2V0aGVy",
		"SSB3YW5uYSBoZWFyIHNvbWUgb2YgdGhlbSBkZWYgcmh5bWVzLCB5b3Uga25vdyB3aGF0IEknbSBzYXlpbic/IC8gQW5kIHRvZ2V0aGVyLCB3ZSBjYW4gZ2V0IHBhaWQgaW4gZnVsbA==",
		"VGhpbmtpbicgb2YgYSBtYXN0ZXIgcGxhbiAvICdDdXogYWluJ3QgbnV0aGluJyBidXQgc3dlYXQgaW5zaWRlIG15IGhhbmQ=",
		"U28gSSBkaWcgaW50byBteSBwb2NrZXQsIGFsbCBteSBtb25leSBpcyBzcGVudCAvIFNvIEkgZGlnIGRlZXBlciBidXQgc3RpbGwgY29taW4nIHVwIHdpdGggbGludA==",
		"U28gSSBzdGFydCBteSBtaXNzaW9uLCBsZWF2ZSBteSByZXNpZGVuY2UgLyBUaGlua2luJyBob3cgY291bGQgSSBnZXQgc29tZSBkZWFkIHByZXNpZGVudHM=",
		"SSBuZWVkIG1vbmV5LCBJIHVzZWQgdG8gYmUgYSBzdGljay11cCBraWQgLyBTbyBJIHRoaW5rIG9mIGFsbCB0aGUgZGV2aW91cyB0aGluZ3MgSSBkaWQ=",
		"SSB1c2VkIHRvIHJvbGwgdXAsIHRoaXMgaXMgYSBob2xkIHVwLCBhaW4ndCBudXRoaW4nIGZ1bm55IC8gU3RvcCBzbWlsaW5nLCBiZSBzdGlsbCwgZG9uJ3QgbnV0aGluJyBtb3ZlIGJ1dCB0aGUgbW9uZXk=",
		"QnV0IG5vdyBJIGxlYXJuZWQgdG8gZWFybiAnY3V6IEknbSByaWdodGVvdXMgLyBJIGZlZWwgZ3JlYXQsIHNvIG1heWJlIEkgbWlnaHQganVzdA==",
		"U2VhcmNoIGZvciBhIG5pbmUgdG8gZml2ZSwgaWYgSSBzdHJpdmUgLyBUaGVuIG1heWJlIEknbGwgc3RheSBhbGl2ZQ==",
		"U28gSSB3YWxrIHVwIHRoZSBzdHJlZXQgd2hpc3RsaW4nIHRoaXMgLyBGZWVsaW4nIG91dCBvZiBwbGFjZSAnY3V6LCBtYW4sIGRvIEkgbWlzcw==",
		"QSBwZW4gYW5kIGEgcGFwZXIsIGEgc3RlcmVvLCBhIHRhcGUgb2YgLyBNZSBhbmQgRXJpYyBCLCBhbmQgYSBuaWNlIGJpZyBwbGF0ZSBvZg==",
		"RmlzaCwgd2hpY2ggaXMgbXkgZmF2b3JpdGUgZGlzaCAvIEJ1dCB3aXRob3V0IG5vIG1vbmV5IGl0J3Mgc3RpbGwgYSB3aXNo",
		"J0N1eiBJIGRvbid0IGxpa2UgdG8gZHJlYW0gYWJvdXQgZ2V0dGluJyBwYWlkIC8gU28gSSBkaWcgaW50byB0aGUgYm9va3Mgb2YgdGhlIHJoeW1lcyB0aGF0IEkgbWFkZQ==",
		"U28gbm93IHRvIHRlc3QgdG8gc2VlIGlmIEkgZ290IHB1bGwgLyBIaXQgdGhlIHN0dWRpbywgJ2N1eiBJJ20gcGFpZCBpbiBmdWxs",
		"UmFraW0sIGNoZWNrIHRoaXMgb3V0LCB5byAvIFlvdSBnbyB0byB5b3VyIGdpcmwgaG91c2UgYW5kIEknbGwgZ28gdG8gbWluZQ==",
		"J0NhdXNlIG15IGdpcmwgaXMgZGVmaW5pdGVseSBtYWQgLyAnQ2F1c2UgaXQgdG9vayB1cyB0b28gbG9uZyB0byBkbyB0aGlzIGFsYnVt",
		"WW8sIEkgaGVhciB3aGF0IHlvdSdyZSBzYXlpbmcgLyBTbyBsZXQncyBqdXN0IHB1bXAgdGhlIG11c2ljIHVw",
		"QW5kIGNvdW50IG91ciBtb25leSAvIFlvLCB3ZWxsIGNoZWNrIHRoaXMgb3V0LCB5byBFbGk=",
		"VHVybiBkb3duIHRoZSBiYXNzIGRvd24gLyBBbmQgbGV0IHRoZSBiZWF0IGp1c3Qga2VlcCBvbiByb2NraW4n",
		"QW5kIHdlIG91dHRhIGhlcmUgLyBZbywgd2hhdCBoYXBwZW5lZCB0byBwZWFjZT8gLyBQZWFjZQ==",
	}
	out := []string{
		`i'm rated "R"...this is a warning, ya better void / P`,
		"cuz I came back to attack others in spite- / Strike l",
		"but don't be afraid in the dark, in a park / Not a sc",
		"ya tremble like a alcoholic, muscles tighten up / Wha",
		"suddenly you feel like your in a horror flick / You g",
		"music's the clue, when I come your warned / Apocalyps",
		"haven't you ever heard of a MC-murderer? / This is th",
		"death wish, so come on, step to this / Hysterical ide",
		"friday the thirteenth, walking down Elm Street / You ",
		"this is off limits, so your visions are blurry / All ",
		"terror in the styles, never error-files / Indeed I'm ",
		"for those that oppose to be level or next to this / I",
		"worse than a nightmare, you don't have to sleep a win",
		"flashbacks interfere, ya start to hear: / The R-A-K-I",
		"then the beat is hysterical / That makes Eric go get ",
		"soon the lyrical format is superior / Faces of death ",
		"mC's decaying, cuz they never stayed / The scene of a",
		"the fiend of a rhyme on the mic that you know / It's ",
		"melodies-unmakable, pattern-unescapable / A horn if w",
		"i bless the child, the earth, the gods and bomb the r",
		"hazardous to your health so be friendly / A matter of",
		"shake 'till your clear, make it disappear, make the n",
		"if not, my soul'll release! / The scene is recreated,",
		"cuz your about to see a disastrous sight / A performa",
		`lyrics of fury! A fearified freestyle! / The "R" is i`,
		"make sure the system's loud when I mention / Phrases ",
		"you want to hear some sounds that not only pounds but",
		"then nonchalantly tell you what it mean to me / Stric",
		"and I don't care if the whole crowd's a witness! / I'",
		"program into the speed of the rhyme, prepare to start",
		"musical madness MC ever made, see it's / Now an emerg",
		"open your mind, you will find every word'll be / Furi",
		"battle's tempting...whatever suits ya! / For words th",
		"you think you're ruffer, then suffer the consequences",
		"i wake ya with hundreds of thousands of volts / Mic-t",
		"novocain ease the pain it might save him / If not, Er",
		"yo Rakim, what's up? / Yo, I'm doing the knowledge, E",
		"well, check this out, since Norby Walters is our agen",
		"kara Lewis is our agent, word up / Zakia and 4th and ",
		"okay, so who we rollin' with then? We rollin' with Ru",
		"check this out, since we talking over / This def beat",
		"i wanna hear some of them def rhymes, you know what I",
		"thinkin' of a master plan / 'Cuz ain't nuthin' but sw",
		"so I dig into my pocket, all my money is spent / So I",
		"so I start my mission, leave my residence / Thinkin' ",
		"i need money, I used to be a stick-up kid / So I thin",
		"i used to roll up, this is a hold up, ain't nuthin' f",
		"but now I learned to earn 'cuz I'm righteous / I feel",
		"search for a nine to five, if I strive / Then maybe I",
		"so I walk up the street whistlin' this / Feelin' out ",
		"a pen and a paper, a stereo, a tape of / Me and Eric ",
		"fish, which is my favorite dish / But without no mone",
		"Cuz I don't like to dream about gettin' paid / So I ",
		"so now to test to see if I got pull / Hit the studio,",
		"rakim, check this out, yo / You go to your girl house",
		"Cause my girl is definitely mad / 'Cause it took us ",
		"yo, I hear what you're saying / So let's just pump th",
		"and count our money / Yo, well check this out, yo Eli",
		"turn down the bass down / And let the beat just keep ",
		"and we outta here / Yo, what happened to peace? / Pea",
	}

	for i := 0; i < 1000; i++ {
		aKey := make([]byte, aes.BlockSize)
		_, _ = rand.Read(aKey)
		nonce := 0
		as := AESStruct{key: aKey}
		ciphers := make([][]byte, len(msg))
		for i := 0; i < len(msg); i++ {
			raw, _ := base64.StdEncoding.DecodeString(msg[i])
			ciphers[i], err = CTRAES(as.key, raw, nonce)
			require.NoError(t, err)
		}
		plain := as.FixedNonceCTRAttackStatistically(ciphers, nonce)
		var outByte = make([][]byte, len(plain))
		for i := 0; i < len(plain); i++ {
			outByte[i] = []byte(out[i])
		}

		if reflect.DeepEqual(outByte, plain) {
			spew.Dump("Success Attack")
			break
		} else {
			continue
		}
	}

}
