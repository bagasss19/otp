### README
This is simple api to generate and validate otp

### Requirement
- Buatlah API untuk generate dan validate OTP
- Boleh menggunakan DB atau tidak, jika menggunakan DB sertakan file migrationnya
- Kode OTP adalah 4 digit numeric
- Maksimal request OTP adalah 3x, jika sudah mencapai limit maka request OTP dapat dilakukan setelah menunggu 60 menit
- Validasi OTP salah maksimal 3x, jika sudah 3x kode OTP tidak dapat digunakan lagi
- Gunakan bahasa pemrograman golang

## Tech Stack
- golang
- gofiber
- swagger

## HOW TO
- after pull the repository, run `make tidy` to update depedencies
- run `make run` to running the app
- go to localhost:3000/swagger/index.html to see api documentation
- it use json file as database(at this case, otp.json), so no need to migrate db