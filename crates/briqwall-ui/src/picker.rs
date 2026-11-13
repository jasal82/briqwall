//! Native "open file" dialog, used to add a program to the list by hand.

use crate::i18n::t;
use briqwall_common::util::wide;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_PATHMUSTEXIST, SIGDN_FILESYSPATH,
};

/// Let the user pick a program. `None` if the dialog was cancelled or failed.
/// Must run on the thread that owns `parent` – the dialog is modal to it.
pub fn pick_executable(parent: isize) -> Option<String> {
    unsafe {
        // The UI thread is usually initialised already; a second call is fine.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;

        let title = wide(t("Programm auswählen", "Choose a program"));
        let _ = dialog.SetTitle(PCWSTR(title.as_ptr()));

        let programs = wide(t("Programme", "Programs"));
        let programs_spec = wide("*.exe");
        let any = wide(t("Alle Dateien", "All files"));
        let any_spec = wide("*.*");
        let types = [
            COMDLG_FILTERSPEC { pszName: PCWSTR(programs.as_ptr()), pszSpec: PCWSTR(programs_spec.as_ptr()) },
            COMDLG_FILTERSPEC { pszName: PCWSTR(any.as_ptr()), pszSpec: PCWSTR(any_spec.as_ptr()) },
        ];
        let _ = dialog.SetFileTypes(&types);

        let options = dialog.GetOptions().ok()?;
        let _ = dialog.SetOptions(options | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST | FOS_FORCEFILESYSTEM);

        // Err also means "user cancelled", which is not an error for us.
        dialog.Show(Some(HWND(parent as *mut _))).ok()?;

        let item = dialog.GetResult().ok()?;
        let path = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
        let text = path.to_string().ok();
        windows::Win32::System::Com::CoTaskMemFree(Some(path.0 as *const _));
        text
    }
}
