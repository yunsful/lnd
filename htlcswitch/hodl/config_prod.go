//go:build !dev
// +build !dev

package hodl

// Config is a struct that can be used to enable certain dev-level hodl flags
// in production.
type Config struct {
	// NOTE: This struct was previously empty in production builds.

	// IgnoreHtlcCancellations instructs the node to ignore incoming HTLC
	// cancellation requests. This will likely cause the upstream peer to
	// force-close the channel.
	IgnoreHtlcCancellations bool `long:"ignore-htlc-cancellations" description:"Instructs the node to ignore incoming HTLC cancellation requests. This will likely cause the upstream peer to force-close the channel."`
}

// Mask returns a mask that is composed of the hodl flags specified in the
// config.
func (c *Config) Mask() Mask {
	// The original implementation returned MaskNone in production.
	// return MaskNone

	var flags []Flag

	if c.IgnoreHtlcCancellations {
		flags = append(flags, IgnoreHtlcCancellations)
	}

	return MaskFromFlags(flags...)
}
