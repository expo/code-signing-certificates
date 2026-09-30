// Jest 28+ exposes Node's global `navigator` object inside the test sandbox. node-forge's
// jsbn BigInteger selects its multiplication routine based on `navigator.appName`, and the
// routine it picks when `navigator` is defined runs roughly 35x slower inside the jest
// sandbox (RSA signing goes from ~15ms to ~600ms). Removing `navigator` before node-forge
// loads restores the routine used when no `navigator` exists (the same one jest 27 used).
delete globalThis.navigator;
