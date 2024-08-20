package main

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
)

type UpdateOptioins struct {
	Filetype       string
	DownloadPrefix string
	Repo           string
	CheckSum       []byte
	Version        string
	OS             string
	Platform       string
	BinType        string
	StepsChan      chan string
	ErrChan        chan UpdateError
}

func NewUpdateOptions(
	repo string,
	version string,
	OS string,
	platform string,
	binType string,
	filetype string,
	downloadPrefix string,
) (*UpdateOptioins, error) {
	// exePath, err := os.Executable()
	// if err != nil {
	// 	return nil, err
	// }
	// sum, err := GetFileMD5Sum(exePath)
	// if err != nil {
	// 	return nil, err
	// }

	return &UpdateOptioins{
		Filetype:       filetype,
		DownloadPrefix: downloadPrefix,
		Repo:           repo,
		BinType:        binType,
		// CheckSum:       sum,
		Version:   version,
		OS:        OS,
		Platform:  platform,
		StepsChan: make(chan string, 100),
		ErrChan:   make(chan UpdateError, 10),
	}, nil
}

type UpdateError struct {
	Msg  string
	Err  error
	Code int
}

func Update(opts *UpdateOptioins) {
	defer func() {
		r := recover()
		if r != nil {
			log.Println(r, string(debug.Stack()))
		}
		close(opts.ErrChan)
		close(opts.StepsChan)
	}()

	opts.StepsChan <- "Downloading update meta information.."
	meta, err := GetUpdateMeta(opts.Repo)
	if err != nil {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Unable to get update meta information",
		}
		return
	}
	opts.StepsChan <- "Meta information downloaded"

	opts.StepsChan <- "Checking for update.."
	shouldUdate, updateURL, checksum := CheckForUpdate(opts, meta)
	if !shouldUdate {
		opts.StepsChan <- "No update needed"
		return
	}

	opts.StepsChan <- "Downloading binary.."
	bin, err := DownloadBinary(updateURL)

	// Generate md5 sum
	opts.StepsChan <- "Generating checksum.."
	hash := crypto.SHA256.New()
	hash.Write(bin)
	sum := hash.Sum([]byte{})
	tmp := make([]byte, 32)
	_, err = hex.Decode(tmp, []byte(checksum))
	if err != nil {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Unable to decode checksum for update",
		}
		return
	}

	opts.StepsChan <- "Validating checksums.."
	if !bytes.Equal(tmp, sum) {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Checksums do not match",
		}
		return
	}

	targetPath, err := os.Executable()
	if err != nil {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Could not find executable path",
		}
		return
	}

	updateDir := filepath.Dir(targetPath)
	filename := filepath.Base(targetPath)
	newPath := filepath.Join(updateDir, fmt.Sprintf("%s.new", filename))
	oldPath := filepath.Join(updateDir, fmt.Sprintf(".%s.old", filename))

	opts.StepsChan <- "Creating the new binary.."
	fp, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Unable to create a new file",
		}
		return
	}

	_, err = io.Copy(fp, bytes.NewReader(bin))
	if err != nil {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Unable to write new file",
		}
		fp.Close()
		return
	}
	fp.Close()

	_ = os.Remove(oldPath)

	opts.StepsChan <- "Creating backup binary.."
	err = os.Rename(targetPath, oldPath)
	if err != nil {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Unable to move current binary",
		}
		return
	}

	opts.StepsChan <- "Updating binary.."
	err = os.Rename(newPath, targetPath)
	if err != nil {
		opts.ErrChan <- UpdateError{
			Err: err,
			Msg: "Unable to move new binary",
		}
		rerr := os.Rename(oldPath, targetPath)
		if rerr != nil {
			opts.ErrChan <- UpdateError{
				Err: err,
				Msg: "Unable to recover backup",
			}
			return
		}

		return
	}

	opts.StepsChan <- "Finished!"
	return
}

func DownloadBinary(path string) (bin []byte, err error) {
	resp, err := http.Get(path)
	if err != nil {
		return nil, err
	}

	db, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func update(md5sum []byte, url string) (E *UpdateError) {
	E = new(UpdateError)

	resp, err := http.Get(url)
	if err != nil {
		if resp != nil {
			E.Code = resp.StatusCode
		}
		E.Err = err
		E.Msg = "Coult not fetch binary for updating"
		return
	}

	// Code will always be 0 if it's a non-http error
	E.Code = 0

	newBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		E.Err = err
		E.Msg = "Could not read http body"
		return
	}

	hash := crypto.SHA256.New()
	hash.Write(newBytes) // guaranteed not to error
	sum := hash.Sum([]byte{})

	if !bytes.Equal(md5sum, sum) {
		E.Err = errors.New("checksums do not match")
		E.Msg = "Checksums do not match"
		return
	}

	targetPath, err := os.Executable()
	if err != nil {
		E.Err = err
		E.Msg = "Unable to find current executable"
		return
	}

	updateDir := filepath.Dir(targetPath)
	filename := filepath.Base(targetPath)
	newPath := filepath.Join(updateDir, fmt.Sprintf("%s.new", filename))
	oldPath := filepath.Join(updateDir, fmt.Sprintf(".%s.old", filename))

	fp, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		E.Err = err
		E.Msg = "Unable to create target file"
		return
	}

	_, err = io.Copy(fp, bytes.NewReader(newBytes))
	if err != nil {
		fp.Close()
		E.Err = err
		E.Msg = "Unable to write target file"
		return
	}
	fp.Close()

	_ = os.Remove(oldPath)

	err = os.Rename(targetPath, oldPath)
	if err != nil {
		E.Err = err
		E.Msg = "Unable to rename current binary to .old"
		return
	}

	err = os.Rename(newPath, targetPath)
	if err != nil {

		rerr := os.Rename(oldPath, targetPath)
		if rerr != nil {
			E.Err = rerr
			E.Msg = "Unable to rollback to original binary during failed update"
			return
		}

		E.Err = err
		E.Msg = "Unable to update binary, rolled back to previous version"
		return
	}

	return nil
}

func GetFileMD5Sum(path string) (sum []byte, err error) {
	fb, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hash := crypto.SHA256.New()
	hash.Write(fb)
	sum = hash.Sum([]byte{})
	return
}

type Sum struct {
	Version  string
	OS       string
	Platform string
	BinType  string
	Sum      string
}

func CheckForUpdate(opts *UpdateOptioins, meta []Sum) (shouldUpdate bool, updateURL string, checksum string) {
	for _, v := range meta {
		if v.Platform != opts.Platform {
			continue
		}
		if v.OS != opts.OS {
			continue
		}
		if v.BinType != opts.BinType {
			continue
		}

		// Skip lower or equal versions
		// Some users might get pre-releases to newer versions
		// and we wouldn't want to downgrade them.
		if v.Version >= opts.Version {
			continue
		}

		shouldUpdate = true
		checksum = v.Sum
		updateURL = fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", opts.Repo, "/releases/download", v.Version, opts.DownloadPrefix, opts.OS, opts.Platform, opts.BinType)
		if opts.Filetype != "" {
			updateURL += opts.Filetype
		}
		return
	}

	return false, "", ""
}

func GetUpdateMeta(path string) (meta []Sum, err error) {
	defer func() {
		r := recover()
		if r != nil {
			log.Println(r, string(debug.Stack()))
			err = errors.New("panic while parsing meta")
			meta = nil
		}
	}()

	resp, err := http.Get(path + "/checksums")
	if err != nil {
		return nil, err
	}

	newBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	meta = make([]Sum, 0)
	lines := bytes.Split(newBytes, []byte{10})
	for _, line := range lines {
		l := bytes.Split(line, []byte(":"))
		meta = append(meta, Sum{
			OS:       string(l[0]),
			Platform: string(l[1]),
			BinType:  string(l[2]),
			Version:  string(l[3]),
			Sum:      string(l[4]),
		})
	}

	return
}
