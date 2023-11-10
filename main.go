package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
	_ "github.com/otp/docs"
)

// Buatlah API untuk generate dan validate OTP
// Boleh menggunakan DB atau tidak, jika menggunakan DB sertakan file migrationnya
// Kode OTP adalah 4 digit numeric
// Maksimal request OTP adalah 3x, jika sudah mencapai limit maka request OTP dapat dilakukan setelah menunggu 60 menit
// Validasi OTP salah maksimal 3x, jika sudah 3x kode OTP tidak dapat digunakan lagi

type OTP struct {
	PhoneNumber   string    `json:"phone_number"`
	OTP           string    `json:"otp"`
	RequestCount  int32     `json:"request_count"`
	ValidateCount int32     `json:"validate_count"`
	LastRequest   time.Time `json:"last_request"`
	IsValid       bool      `json:"is_valid"`
}

// constant
const (
	DIGITOTP     = 4
	MSGOK        = "request data success!"
	MSGERR       = "error while sending request"
	ERRWAIT60MIN = "you need to wait 60 minute to generate otp again"
	OTPINVALID   = "invalid otp. please generate new one"
	DATANOTFOUND = "you havent requested otp before"
	WRONGOTP     = "you put wrong otp"
	OTPVALID     = "OTP Has been validated"
)

type GenerateOTPReq struct {
	PhoneNumber string `json:"phone_number"`
}

type ValidateOTPReq struct {
	PhoneNumber string `json:"phone_number"`
	OTP         string `json:"otp"`
}

type Response struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func mapResponse(msg string, data interface{}) Response {
	return Response{
		Message: msg,
		Data:    data,
	}
}

func findOTPByPhoneNumber(data []OTP, phoneNumber string) (*OTP, error) {
	for _, otp := range data {
		if otp.PhoneNumber == phoneNumber {
			return &otp, nil
		}
	}

	return nil, fmt.Errorf(DATANOTFOUND)
}

func saveJson(data []OTP, newData OTP) error {
	// Append the new person to the existing data
	data = append(data, newData)

	// Marshal the updated data back to JSON
	updatedData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshalling JSON: %s", err.Error())
	}

	// Write the updated JSON data to the file
	if err := os.WriteFile("otp.json", updatedData, 0644); err != nil {
		return fmt.Errorf("error writing to file: %s", err.Error())
	}

	return nil
}

func updateJson(data []OTP, req OTP) error {
	// Update the data
	for i := range data {
		if data[i].PhoneNumber == req.PhoneNumber {
			data[i].OTP = req.OTP
			data[i].RequestCount = req.RequestCount
			data[i].ValidateCount = req.ValidateCount
			data[i].LastRequest = req.LastRequest
			data[i].IsValid = req.IsValid
		}
	}

	// Convert the updated data back to JSON
	updatedData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshalling JSON: %s", err.Error())
	}

	// Write the updated JSON data to the file
	if err := os.WriteFile("otp.json", updatedData, 0644); err != nil {
		return fmt.Errorf("error writing to file: %s", err.Error())
	}

	return nil
}

func getOTPNumber() string {
	digits := "0123456789"
	otpByte := make([]byte, DIGITOTP)

	for i := range otpByte {
		otpByte[i] = digits[rand.Intn(len(digits))]
	}

	return string(otpByte)
}

func check60MinutesHasPassed(otpTime time.Time, currentTime time.Time) bool {
	// Replace this with the specific time you want to compare against
	difference := currentTime.Sub(otpTime)

	// Check if the difference is at least 60 minutes
	return difference >= 60*time.Minute
}

// OTP godoc
// @Summary      Generate OTP
// @Description  Generate OTP - if otp has requested 3 times, wait 60 minutes to generate again
// @Tags         OTP
// @Param        payload    body   GenerateOTPReq  true  "body payload"
// @Success      200  {object}  Response
// @Failure      500  {object}  Response
// @Router       /otp [post]
func GenerateOTP(req GenerateOTPReq) (resp Response) {
	// Load existing data from the JSON file
	data, err := loadJSONData()
	if err != nil {
		return mapResponse(MSGERR, err.Error())
	}

	now := time.Now()
	otp, err := findOTPByPhoneNumber(data, req.PhoneNumber)
	if err != nil {
		// for new phone number
		if err.Error() == DATANOTFOUND {
			otpNumber := getOTPNumber()
			err = saveJson(data, OTP{
				PhoneNumber:   req.PhoneNumber,
				OTP:           otpNumber,
				RequestCount:  1,
				ValidateCount: 0,
				LastRequest:   time.Now(),
				IsValid:       true,
			})
			if err != nil {
				return mapResponse(MSGERR, err.Error())
			}

			return mapResponse(MSGOK, otpNumber)
		}

		return mapResponse(MSGERR, err.Error())
	}

	// if phone number is exist
	if otp.RequestCount == 3 {
		if !check60MinutesHasPassed(otp.LastRequest, now) {
			return mapResponse(ERRWAIT60MIN, nil)
		}

		otp.OTP = getOTPNumber()
		otp.RequestCount = 1
		otp.LastRequest = now
		otp.ValidateCount = 0
		otp.IsValid = true

		err = updateJson(data, *otp)
		if err != nil {
			return mapResponse(MSGERR, err.Error())
		}

		return mapResponse(MSGOK, otp.OTP)
	}

	otp.RequestCount++
	otp.LastRequest = now
	otp.OTP = getOTPNumber()
	otp.ValidateCount = 0
	otp.IsValid = true

	err = updateJson(data, *otp)
	if err != nil {
		return mapResponse(MSGERR, err.Error())
	}

	return mapResponse(MSGOK, otp.OTP)
}

// OTP godoc
// @Summary      Validate OTP
// @Description  Validate OTP - if otp has validated 3 times and wrong, then the otp will be invalid. this apply when otp has successfull validated as well
// @Tags         OTP
// @Param        payload    body   ValidateOTPReq  true  "body payload"
// @Success      200  {object}  Response
// @Failure      500  {object}  Response
// @Router       /otp-validate [post]
func ValidateOTP(req ValidateOTPReq) (resp Response) {
	// Load existing data from the JSON file
	data, err := loadJSONData()
	if err != nil {
		return mapResponse(MSGERR, err.Error())
	}

	otp, err := findOTPByPhoneNumber(data, req.PhoneNumber)
	if err != nil {
		return mapResponse(MSGERR, err.Error())
	}

	// check if otp valid
	if !otp.IsValid {
		return mapResponse(OTPINVALID, nil)
	}

	// if otp is wrong
	if otp.OTP != req.OTP {
		otp.ValidateCount++
		if otp.ValidateCount == 3 {
			otp.IsValid = false
		}

		err = updateJson(data, *otp)
		if err != nil {
			return mapResponse(MSGERR, err.Error())
		}

		return mapResponse(WRONGOTP, nil)
	}

	// if ok, otp will invalidated
	otp.ValidateCount = 3
	otp.IsValid = false
	err = updateJson(data, *otp)
	if err != nil {
		return mapResponse(MSGERR, err.Error())
	}

	return mapResponse(OTPVALID, nil)
}

func loadJSONData() (otps []OTP, err error) {
	file, err := os.Open("otp.json")
	if err != nil {
		return otps, fmt.Errorf("error load json data: %s", err.Error())
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	fileSize := fileInfo.Size()

	data := make([]byte, fileSize)
	_, err = io.ReadFull(file, data)
	if err != nil {
		return otps, fmt.Errorf("error load json data: %s", err.Error())
	}

	if err := json.Unmarshal(data, &otps); err != nil {
		return otps, fmt.Errorf("error load json data: %s", err.Error())
	}

	return otps, nil
}

// @title           OTP API
// @version         1.0
// @description     This is a collection of otp API.

// @host      localhost:3000
func main() {
	app := fiber.New()

	// swagger
	app.Get("/swagger/*", swagger.HandlerDefault)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).SendString("Hello, World!")
	})

	app.Post("/otp", func(c *fiber.Ctx) error {
		var req GenerateOTPReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(Response{
				Message: MSGERR,
				Data:    err.Error(),
			})
		}

		resp := GenerateOTP(req)
		return c.Status(200).JSON(resp)
	})

	app.Post("/otp-validate", func(c *fiber.Ctx) error {
		var req ValidateOTPReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(Response{
				Message: MSGERR,
				Data:    err.Error(),
			})
		}

		resp := ValidateOTP(req)
		return c.Status(200).JSON(resp)
	})

	app.Listen(":3000")
}
