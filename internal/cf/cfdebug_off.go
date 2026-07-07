//go:build darwin && !keychain_cfdebug

package cf

// onCreate and onRelease are no-ops unless the keychain_cfdebug build tag is
// set. The compiler inlines the empty bodies away, so reference accounting costs
// nothing in a normal build.
func onCreate()  {}
func onRelease() {}
