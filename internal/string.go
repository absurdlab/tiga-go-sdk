package internal

// Coalesce returns the first non-empty string.
func Coalesce(elem ...string) string {
	for _, each := range elem {
		if len(each) > 0 {
			return each
		}
	}
	return ""
}
