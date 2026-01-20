package image

import (
	"crypto/aes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// ImageKeyResult 存储图片密钥结果
type ImageKeyResult struct {
	AESKey string
	XORKey string
}

// Extractor 图片密钥提取器
type Extractor struct{}

// NewExtractor 创建新的图片密钥提取器
func NewExtractor() *Extractor {
	return &Extractor{}
}

// GetImageKey 获取图片密钥
func (e *Extractor) GetImageKey(dataDir string, pid uint32) (string, string, error) {
	log.Info().Str("dataDir", dataDir).Uint32("pid", pid).Msg("开始获取图片密钥")

	// 1. 查找模板文件
	templateFiles, err := e.findTemplateDatFiles(dataDir)
	if err != nil {
		return "", "", fmt.Errorf("查找模板文件失败: %v", err)
	}
	if len(templateFiles) == 0 {
		return "", "", fmt.Errorf("未找到模板文件")
	}

	// 2. 计算 XOR 密钥
	xorKey, err := e.getXorKey(templateFiles)
	if err != nil {
		return "", "", fmt.Errorf("计算 XOR 密钥失败: %v", err)
	}
	log.Info().Str("xorKey", fmt.Sprintf("0x%X", xorKey)).Msg("获取到 XOR 密钥")

	// 3. 获取加密的模板数据用于验证
	ciphertext, err := e.getCiphertextFromTemplate(templateFiles)
	if err != nil {
		return "", "", fmt.Errorf("获取加密模板数据失败: %v", err)
	}

	// 4. 扫描内存获取 AES 密钥
	aesKey, err := e.getAesKeyFromMemory(pid, ciphertext)
	if err != nil {
		return "", "", fmt.Errorf("内存扫描获取 AES 密钥失败: %v", err)
	}
	log.Info().Str("aesKey", aesKey).Msg("获取到 AES 密钥")

	return aesKey, fmt.Sprintf("0x%X", xorKey), nil
}

// findTemplateDatFiles 查找模板图片文件
func (e *Extractor) findTemplateDatFiles(rootDir string) ([]string, error) {
	var files []string
	maxFiles := 32

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if len(files) >= maxFiles {
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".dat") && (strings.HasPrefix(name, "_t") || strings.HasSuffix(name, "_t.dat")) {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// getXorKey 计算 XOR 密钥
func (e *Extractor) getXorKey(templateFiles []string) (byte, error) {
	counts := make(map[byte]int)
	tailSignatures := [][]byte{
		{0xFF, 0xD9}, // JPG end
		{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}, // PNG end
	}

	for _, file := range templateFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		for _, signature := range tailSignatures {
			if len(data) < len(signature) {
				continue
			}
			tail := data[len(data)-len(signature):]
			xorKey := tail[0] ^ signature[0]
			valid := true
			for i := 1; i < len(signature); i++ {
				if (tail[i] ^ xorKey) != signature[i] {
					valid = false
					break
				}
			}
			if valid {
				counts[xorKey]++
			}
		}
	}

	if len(counts) == 0 {
		return 0, fmt.Errorf("cannot calculate xor key")
	}

	// Find most frequent key
	var bestKey byte
	var bestCount int
	for key, count := range counts {
		if count > bestCount {
			bestCount = count
			bestKey = key
		}
	}
	return bestKey, nil
}

// getCiphertextFromTemplate 获取加密模板数据
func (e *Extractor) getCiphertextFromTemplate(templateFiles []string) ([]byte, error) {
	for _, file := range templateFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if len(data) < 0x1f {
			continue
		}

		// Check V4 magic header
		// 0x07 0x08 0x56 0x32 0x08 0x07
		if data[0] == 0x07 && data[1] == 0x08 && data[2] == 0x56 && data[3] == 0x32 && data[4] == 0x08 && data[5] == 0x07 {
			return data[0x0f:0x1f], nil // Return 16 bytes ciphertext
		}
	}
	return nil, fmt.Errorf("not found valid V4 template file")
}

// getAesKeyFromMemory 从内存扫描 AES 密钥
func (e *Extractor) getAesKeyFromMemory(pid uint32, ciphertext []byte) (string, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	openProcess := kernel32.NewProc("OpenProcess")
	readProcessMemory := kernel32.NewProc("ReadProcessMemory")
	virtualQueryEx := kernel32.NewProc("VirtualQueryEx")
	closeHandle := kernel32.NewProc("CloseHandle")

	const (
		PROCESS_QUERY_INFORMATION = 0x0400
		PROCESS_VM_READ           = 0x0010
		MEM_COMMIT                = 0x1000
		MEM_PRIVATE               = 0x20000
		MEM_MAPPED                = 0x40000
		MEM_IMAGE                 = 0x1000000
		PAGE_NOACCESS             = 0x01
		PAGE_GUARD                = 0x100
	)

	hProcess, _, err := openProcess.Call(uintptr(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ), 0, uintptr(pid))
	if hProcess == 0 {
		return "", fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer closeHandle.Call(hProcess)

	var mbi windows.MemoryBasicInformation
	address := uintptr(0)
	maxAddress := uintptr(0x7fffffffffff) // User space limit (approx)

	chunkSize := 4 * 1024 * 1024

	log.Debug().Msg("开始内存扫描...")

	for address < maxAddress {
		ret, _, _ := virtualQueryEx.Call(hProcess, address, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
		if ret == 0 {
			break
		}

		if mbi.State == MEM_COMMIT && (mbi.Protect&PAGE_NOACCESS) == 0 && (mbi.Protect&PAGE_GUARD) == 0 {
			if mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE {
				// Scan this region
				if mbi.RegionSize > 100*1024*1024 { // Skip too large regions
					address += mbi.RegionSize
					continue
				}

				regionBase := mbi.BaseAddress
				regionSize := mbi.RegionSize
				var offset uintptr = 0
				var trailing []byte

				for offset < regionSize {
					readSize := uintptr(chunkSize)
					remaining := regionSize - offset
					if remaining < readSize {
						readSize = remaining
					}

					buffer := make([]byte, readSize)
					var bytesRead uintptr
					ret, _, _ := readProcessMemory.Call(hProcess, regionBase+offset, uintptr(unsafe.Pointer(&buffer[0])), readSize, uintptr(unsafe.Pointer(&bytesRead)))

					if ret != 0 && bytesRead > 0 {
						dataToScan := buffer[:bytesRead]
						if len(trailing) > 0 {
							dataToScan = append(trailing, dataToScan...)
						}

						// Scan dataToScan
						if key, found := e.scanBuffer(dataToScan, ciphertext); found {
							return key, nil
						}

						// Updates for next chunk
						start := len(dataToScan) - 65
						if start < 0 {
							start = 0
						}
						trailing = dataToScan[start:]
					}

					offset += readSize
				}
			}
		}

		address += mbi.RegionSize
	}

	return "", fmt.Errorf("AES key not found in memory")
}

func (e *Extractor) scanBuffer(data []byte, ciphertext []byte) (string, bool) {
	// 1. Scan for pure ASCII keys (32 bytes)
	// Reference Logic: /[^a-zA-Z0-9][a-zA-Z0-9]{32}[^a-zA-Z0-9]/
	// Needs 34 bytes window: 1 head, 32 body, 1 tail
	if len(data) >= 34 {
		for i := 0; i < len(data)-34; i++ {
			// Check header (not alphanum)
			if isAlphaNumAscii(data[i]) {
				continue
			}

			// Check key body (32 chars alphanum)
			valid := true
			for j := 1; j <= 32; j++ {
				if !isAlphaNumAscii(data[i+j]) {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}

			// Check footer (not alphanum)
			if isAlphaNumAscii(data[i+33]) {
				continue
			}

			// Verify
			keyBytes := data[i+1 : i+33]
			if e.verifyKey(ciphertext, keyBytes[:16]) {
				return string(keyBytes), true
			}
		}
	}

	// 2. Scan for UTF-16 ASCII keys
	// e.g. "k.e.y." -> 64 bytes
	// Logic: /[^a-zA-Z0-9][a-zA-Z0-9]{32}[^a-zA-Z0-9]/ but spaced with nulls
	// Window: 2 (head) + 64 (body) + 2 (tail) = 68 bytes?
	// Reference code loop: for (var i = 0; i < dataToScan.length - 65; i++)
	// It calls _isUtf16AsciiKey(data, i).
	// _isUtf16AsciiKey checks 32 * 2 = 64 bytes starting at i.
	// IT DOES NOT CHECK BOUNDARIES in _isUtf16AsciiKey?
	// Wait, reference code for UTF-16:
	/*
				for (var i = 0; i < dataToScan.length - 65; i++) {
		            if (!_isUtf16AsciiKey(dataToScan, i)) {
		              continue;
		            }
					// ... verify
				}
	*/
	// It seems reference code DOES NOT check boundaries for UTF-16?
	// "兼容UTF-16LE存储的32字节ASCII密钥"
	// But let's check strictness. `_isUtf16AsciiKey` checks strict pattern `byte 0x00`.

	if len(data) >= 64 {
		for i := 0; i <= len(data)-64; i++ {
			if !isUtf16AsciiKey(data, i) {
				continue
			}
			// Extract key
			keyBytes := make([]byte, 32)
			for j := 0; j < 32; j++ {
				keyBytes[j] = data[i+j*2]
			}

			if e.verifyKey(ciphertext, keyBytes[:16]) {
				return string(keyBytes), true
			}
		}
	}

	return "", false
}

func isAlphaNumAscii(b byte) bool {
	return (b >= 0x61 && b <= 0x7a) || (b >= 0x41 && b <= 0x5a) || (b >= 0x30 && b <= 0x39)
}

func isUtf16AsciiKey(buf []byte, start int) bool {
	if start+64 > len(buf) {
		return false
	}
	for j := 0; j < 32; j++ {
		charByte := buf[start+j*2]
		nullByte := buf[start+j*2+1]
		if nullByte != 0x00 || !isAlphaNumAscii(charByte) {
			return false
		}
	}
	return true
}

func (e *Extractor) verifyKey(ciphertext []byte, key []byte) bool {
	// AES-128-ECB decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}

	if len(ciphertext) < aes.BlockSize {
		return false
	}

	decrypted := make([]byte, len(ciphertext))
	block.Decrypt(decrypted, ciphertext)

	// Check signatures
	// JPG: FF D8 FF
	if len(decrypted) >= 3 && decrypted[0] == 0xFF && decrypted[1] == 0xD8 && decrypted[2] == 0xFF {
		return true
	}

	// PNG: 89 50 4E 47 0D 0A 1A 0A
	if len(decrypted) >= 8 &&
		decrypted[0] == 0x89 && decrypted[1] == 0x50 && decrypted[2] == 0x4E && decrypted[3] == 0x47 &&
		decrypted[4] == 0x0D && decrypted[5] == 0x0A && decrypted[6] == 0x1A && decrypted[7] == 0x0A {
		return true
	}

	return false
}
