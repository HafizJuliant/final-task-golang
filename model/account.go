package model

type Account struct {
	AccountID int64  `json:"account_id" gorm:"primaryKey;autoIncrement;<-:false"`
	Name      string `json:"name"`
	Balance   int64  `json:"balance"`
}
