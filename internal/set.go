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

func (s Set) All(criteria func(element string) bool) bool {
	for e := range s {
		if ok := criteria(e); !ok {
			return false
		}
	}
	return true
}

func (s Set) Any(criteria func(element string) bool) bool {
	for e := range s {
		if ok := criteria(e); ok {
			return true
		}
	}
	return false
}

func (s Set) ContainsAll(t Set) bool {
	return t.All(s.Contains)
}

func (s Set) ContainsAny(t Set) bool {
	return t.Any(s.Contains)
}
