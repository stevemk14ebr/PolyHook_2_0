#pragma once

// This header defines utilities that are not meant to be used by the users of this library

#ifdef PLH_DIAGNOSTICS
#define PLH_SET_DIAGNOSTIC(DIAGNOSTIC) setDiagnostic(DIAGNOSTIC)
#else
#define PLH_SET_DIAGNOSTIC(DIAGNOSTIC)
#endif
