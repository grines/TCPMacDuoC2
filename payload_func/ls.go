package syscall

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/djherbis/atime"
)

type FileBrowser struct {
	Files        []FileData     `json:"files"`
	IsFile       bool           `json:"is_file"`
	Permissions  PermissionJSON `json:"permissions"`
	Filename     string         `json:"name"`
	ParentPath   string         `json:"parent_path"`
	Success      bool           `json:"success"`
	FileSize     int64          `json:"size"`
	LastModified string         `json:"modify_time"`
	LastAccess   string         `json:"access_time"`
}

type PermissionJSON struct {
	Permissions FilePermission `json:"permissions"`
}

type FileData struct {
	IsFile       bool           `json:"is_file"`
	Permissions  PermissionJSON `json:"permissions"`
	Name         string         `json:"name"`
	FullName     string         `json:"full_name"`
	FileSize     int64          `json:"size"`
	LastModified string         `json:"modify_time"`
	LastAccess   string         `json:"access_time"`
}

type FilePermission struct {
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	Permissions string `json:"permissions"`
	User        string `json:"user,omitempty"`
	Group       string `json:"group,omitempty"`
}

const (
	layoutStr = "01/02/2006 15:04:05"
)

func List(path string) ([]string, error) {
	var data []string
	var e FileBrowser

	abspath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	dirInfo, err := os.Stat(abspath)
	if err != nil {
		return nil, fmt.Errorf("failed to get directory info: %w", err)
	}

	e.IsFile = !dirInfo.IsDir()
	e.Permissions.Permissions = GetPermission(dirInfo)
	e.Filename = dirInfo.Name()
	e.ParentPath = filepath.Dir(abspath)
	if strings.Compare(e.ParentPath, e.Filename) == 0 {
		e.ParentPath = ""
	}
	e.FileSize = dirInfo.Size()
	e.LastModified = dirInfo.ModTime().Format(layoutStr)
	at, err := atime.Stat(abspath)
	if err != nil {
		e.LastAccess = ""
	} else {
		e.LastAccess = at.Format(layoutStr)
	}
	e.Success = true

	if dirInfo.IsDir() {
		files, err := ioutil.ReadDir(abspath)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		fileEntries := make([]FileData, len(files))
		for i, file := range files {
			fileEntries[i].IsFile = !file.IsDir()
			fileEntries[i].Permissions.Permissions = GetPermission(file)
			fileEntries[i].Name = file.Name()
			fileEntries[i].FullName = filepath.Join(abspath, file.Name())
			fileEntries[i].FileSize = file.Size()
			fileEntries[i].LastModified = file.ModTime().Format(layoutStr)
			at, err := atime.Stat(fileEntries[i].FullName)
			if err != nil {
				fileEntries[i].LastAccess = ""
			} else {
				fileEntries[i].LastAccess = at.Format(layoutStr)
			}
		}
		e.Files = fileEntries
	}

	for _, f := range e.Files {
		line := fmt.Sprintf("%s %s %s %s %s %s", f.FullName, f.LastAccess, f.LastModified, f.Permissions.Permissions.User, f.Permissions.Permissions.Group, f.Permissions.Permissions.Permissions)
		data = append(data, line)
	}

	return data, nil
}

func GetPermission(finfo os.FileInfo) FilePermission {
	perms := FilePermission{}
	perms.Permissions = finfo.Mode().Perm().String()
	systat := finfo.Sys().(*syscall.Stat_t)
	if systat != nil {
		perms.UID = int(systat.Uid)
		perms.GID = int(systat.Gid)
		tmpUser, err := user.LookupId(strconv.Itoa(perms.UID))
		if err == nil {
			perms.User = tmpUser.Username
		}
		tmpGroup, err := user.LookupGroupId(strconv.Itoa(perms.GID))
		if err == nil {
			perms.Group = tmpGroup.Name
		}
	}
	return perms
}
