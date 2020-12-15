package internal

func NewSet(values ...string) Set {
	s := Set{}
	for _, value := range values {
		s[value] = struct{}{}
	}
	return s
}

type Set map[string]struct{}

func (s Set) Contains(value string) bool {
	_, contains := s[value]
	return contains
}

func (s Set) ContainsAny(values []string) bool {
	for _, value := range values {
		if s.Contains(value) {
			return true
		}
	}
	return false
}
