// Compilación cruzada a Windows desde otro sistema: unrar_sys elige sus
// fuentes y librerías con cfg(windows) del ANFITRIÓN, así que aquí aportamos lo
// que omite (isnt.cpp y las librerías del sistema). En un anfitrión Windows
// (p. ej. el runner de GitHub Actions) no se hace nada.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tools/mingw-shim/isnt_cruzado.cpp");
    let destino = std::env::var("TARGET").unwrap_or_default();
    let anfitrion = std::env::var("HOST").unwrap_or_default();
    if destino.contains("windows") && !anfitrion.contains("windows") {
        // Objeto suelto en la línea de enlace: se incluye siempre, sin depender
        // del orden respecto a la librería de unrar_sys.
        let objetos = cc::Build::new()
            .cpp(true)
            .file("tools/mingw-shim/isnt_cruzado.cpp")
            .cpp_link_stdlib(None)
            .warnings(false)
            .compile_intermediates();
        for o in objetos {
            println!("cargo:rustc-link-arg={}", o.display());
        }
        for lib in ["powrprof", "shell32", "ole32", "oleaut32", "advapi32", "user32"] {
            println!("cargo:rustc-link-lib={lib}");
        }
        // libstdc++ estática para que el .exe siga siendo portable (sin DLLs de mingw).
        println!("cargo:rustc-link-arg=-static-libstdc++");
        println!("cargo:rustc-link-arg=-static-libgcc");
        println!("cargo:rustc-link-lib=static=stdc++");
    }
}
