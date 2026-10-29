package protocol

type UserUpdater[T any] interface {
	UpdateUsers(users []T) error
}

func UserKey(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}
