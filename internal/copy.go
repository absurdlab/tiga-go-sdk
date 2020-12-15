package internal

func CopyArray(src []string) []string {
	if src == nil {
		return nil
	}
	cp := make([]string, len(src))
	copy(cp, src)
	return cp
}

func CopyBool(src *bool) *bool {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}
