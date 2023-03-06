package cloudsploit

import "fmt"

// EmptyOutputError sometimes happen caused by cloudsploit bug(#557). It will may be recovered by re-scanninng.
// ref https://github.com/aquasecurity/cloudsploit/issues/557
type EmptyOutputError struct {
	error
}

func (e EmptyOutputError) Error() string {
	return fmt.Sprintf("[EmptyOutputError] %s", e.error.Error())
}
