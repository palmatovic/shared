package database

// GetDB open new connection pool.
// This method has to be invoked only once, maybe you have to make some tuning for pool size

//type Format int64

//const (
//	LeftJoin Format = iota
//	TableColumn
//)
//
//func (df Format) Format(params ...string) string {
//	switch df {
//	case LeftJoin:
//		return fmt.Sprintf("LEFT JOIN %s ON %s.%s=%s.%s ", params[0], params[0], params[1], params[2], params[3])
//	case TableColumn:
//		return strings.Join([]string{params[0], ".", params[1]}, optional.EmptyString().Value())
//	}
//	return optional.EmptyString().Value()
//}
