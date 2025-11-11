const fs = require('fs');
const path = require('path');

// 1. Tentukan path
const imageDir = path.join(__dirname, '..', 'public', 'images');
const manifestPath = path.join(__dirname, '..', 'public', 'image-manifest.json');

console.log(`Memindai direktori: ${imageDir}`);

// Fungsi rekursif untuk membaca semua file
function getAllFiles(dirPath, arrayOfFiles) {
    const files = fs.readdirSync(dirPath);

    arrayOfFiles = arrayOfFiles || [];

    files.forEach(function(file) {
        if (fs.statSync(path.join(dirPath, file)).isDirectory()) {
            // Jika ini direktori, panggil lagi secara rekursif
            arrayOfFiles = getAllFiles(path.join(dirPath, file), arrayOfFiles);
        } else {
            // Jika ini file, tambahkan ke daftar
            arrayOfFiles.push(path.join(dirPath, file));
        }
    });

    return arrayOfFiles;
}

try {
    // 2. Baca semua file
    const allFiles = getAllFiles(imageDir);

    // 3. Ubah path absolut menjadi path URL publik (relatif terhadap folder 'public')
    const publicDir = path.join(__dirname, '..', 'public');
    const urlList = allFiles
        .map(file => {
            // Buat path relatif
            return path.relative(publicDir, file)
                       // Ganti backslash (Windows) menjadi forward slash (URL)
                       .replace(/\\/g, '/'); 
        })
        .filter(file => 
            // Pastikan kita hanya menyertakan format gambar yang umum
            /\.(jpe?g|png|gif|webp|svg)$/i.test(file) 
        )
        // Tambahkan slash di awal agar menjadi URL absolut dari root
        .map(file => `/${file}`); 

    // 4. Tulis ke file manifest
    fs.writeFileSync(manifestPath, JSON.stringify(urlList, null, 2));

    console.log(`Sukses! ${urlList.length} gambar ditulis ke ${manifestPath}`);

} catch (e) {
    console.error(`Gagal membuat image manifest: ${e.message}`);
    // Jika direktori tidak ada, buat file kosong agar build tidak gagal
    if (!fs.existsSync(manifestPath)) {
        fs.writeFileSync(manifestPath, JSON.stringify([]));
        console.warn("Membuat image-manifest.json kosong.");
    }
}
