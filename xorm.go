package oxorm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/mgo.v2/bson"

	"github.com/chinahdkj/osin"
	"github.com/chinahdkj/xorm"
)

type OauthClient struct {
	Id          string  `json:"id" xorm:"pk VARCHAR(255) NOT NULL"`
	Secret      string  `json:"secret" xorm:"VARCHAR(255) NOT NULL"`
	Extra       *string `json:"extra" xorm:"VARCHAR(255) NULL"`
	RedirectUri *string `json:"redirect_uri" xorm:"VARCHAR(255) NULL"`
}

// Client id
func (this *OauthClient) GetId() string {
	return this.Id
}

func (this *OauthClient) ClientSecretMatches(secret string) bool {

	return strings.ToUpper(SHA256(this.Id, "$", this.Secret)) == strings.ToUpper(secret)
}

// Client secret
func (this *OauthClient) GetSecret() string {
	return this.Secret
}

// Base client uri
func (this *OauthClient) GetRedirectUri() string {

	if this.RedirectUri == nil {
		return ""
	}

	return *this.RedirectUri
}

// Data to be passed to storage. Not used by the library.
func (this *OauthClient) GetUserData() interface{} {
	return this.Extra
}

type OauthAuthorize struct {
	Client      string  `json:"client" xorm:"VARCHAR(255) NOT NULL"`
	Code        string  `json:"code" xorm:"pk VARCHAR(255) NOT NULL"`
	ExpiresIn   int64   `json:"expires_in" xorm:"INT(20) NOT NULL"`
	Scope       *string `json:"scope" xorm:"VARCHAR(255) NULL"`
	RedirectUri string  `json:"redirect_uri" xorm:"VARCHAR(255) NOT NULL"`
	State       *string `json:"state" xorm:"VARCHAR(255) NULL"`
	Extra       *string `json:"extra" xorm:"VARCHAR(255) NULL"`
	CreatedAt   int64   `json:"created_at" xorm:"INT(20) NOT NULL"`
}

type OauthAccess struct {
	AccessToken  string  `json:"access_token" xorm:"pk VARCHAR(255) NOT NULL"`
	Client       string  `json:"client" xorm:"VARCHAR(255) NOT NULL"`
	Authorize    *string `json:"authorize" xorm:"VARCHAR(255) NULL"`
	Previous     *string `json:"previous" xorm:"VARCHAR(255) NULL"`
	RefreshToken *string `json:"refresh_token" xorm:"VARCHAR(255) NULL"`
	ExpiresIn    int64   `json:"expires_in" xorm:"INT(20) NOT NULL"`
	Scope        *string `json:"scope" xorm:"VARCHAR(255) NULL"`
	RedirectUri  string  `json:"redirect_uri" xorm:"VARCHAR(255) NOT NULL"`
	Extra        *string `json:"extra" xorm:"VARCHAR(255) NULL"`
	CreatedAt    int64   `json:"created_at" xorm:"INT(20) NOT NULL"`
}

type OauthRefresh struct {
	Token  string `json:"token" xorm:"pk VARCHAR(255) NOT NULL"`
	Access string `json:"access" xorm:"VARCHAR(255) NOT NULL"`
}

type OauthExpires struct {
	Id        string `json:"id" xorm:"pk VARCHAR(255) NOT NULL"`
	Token     string `json:"token" xorm:"index VARCHAR(255) NOT NULL"`
	ExpiresAt int64  `json:"expires_at" xorm:"index INT(20) NOT NULL"`
}

// Storage implements interface "github.com/RangelReale/osin".Storage and interface "github.com/felipeweb/osin-mysql/storage".Storage
type Storage struct {
	db *xorm.Engine
}

// New returns a new mysql storage instance.
func New(db *xorm.Engine) *Storage {
	return &Storage{db}
}

// CreateSchemas creates the schemata, if they do not exist yet in the database. Returns an error if something went wrong.
func (s *Storage) CreateSchemas() error {
	return s.db.Sync2(new(OauthClient), new(OauthAuthorize), new(OauthAccess), new(OauthRefresh), new(OauthExpires))
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *Storage) Clone() osin.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *Storage) Close() {
}

// GetClient loads the client by id
func (s *Storage) GetClient(id string) (osin.Client, error) {

	client := &OauthClient{}
	ok, err := s.db.Table(client).Where("id=?", id).Get(client)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, osin.ErrNotFound
	}

	return client, nil
}

// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
func (s *Storage) UpdateClient(c osin.Client) error {

	sql := fmt.Sprintf(`UPDATE %s
		SET secret=?, redirect_uri=?, 
		extra=? WHERE id=?`, s.db.TableMapper.Obj2Table("oauth_client"))
	_, err := s.db.Exec(sql, c.GetSecret(), c.GetRedirectUri(), c.GetUserData(), c.GetId())

	return err
}

// CreateClient stores the client in the database and returns an error, if something went wrong.
func (s *Storage) CreateClient(c osin.Client) error {

	var extra *string
	switch c.GetUserData().(type) {
	case string:
		s := c.GetUserData().(string)
		extra = &s
	case *string:
		extra = c.GetUserData().(*string)
	default:
		return errors.New("Unsupported type!")
	}

	rd := c.GetRedirectUri()

	client := &OauthClient{
		Id:          c.GetId(),
		Secret:      c.GetSecret(),
		Extra:       extra,
		RedirectUri: &rd,
	}

	_, err := s.db.Insert(client)

	return err
}

// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
func (s *Storage) RemoveClient(id string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s where ID=?", s.db.TableMapper.Obj2Table("oauth_client")), id)
	return err
}

// SaveAuthorize saves authorize data.
func (s *Storage) SaveAuthorize(data *osin.AuthorizeData) error {

	c := data.Client
	var extra *string

	switch c.GetUserData().(type) {
	case string:
		s := c.GetUserData().(string)
		extra = &s
	case *string:
		extra = c.GetUserData().(*string)
	default:
		return errors.New("Unsupported type!")
	}

	st := data.State

	authorize := OauthAuthorize{
		Client:      data.Client.GetId(),
		Code:        data.Code,
		ExpiresIn:   int64(data.ExpiresIn),
		RedirectUri: data.RedirectUri,
		State:       &st,
		CreatedAt:   data.CreatedAt.Unix(),
		Extra:       extra,
	}

	if _, err := s.db.Insert(&authorize); err != nil {
		return err
	}

	if err := s.AddExpireAtData(data.Code, data.ExpireAt()); err != nil {
		return err
	}

	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {

	var ok bool
	var err error
	data := OauthAuthorize{}

	if ok, err = s.db.Table(&data).Where("code = ?", code).Limit(1).Get(&data); err != nil {
		return nil, err
	}

	if !ok {
		return nil, osin.ErrNotFound
	}

	cid := data.Client

	authorize := osin.AuthorizeData{
		Code:        data.Code,
		ExpiresIn:   int32(data.ExpiresIn),
		Scope:       "",
		RedirectUri: data.RedirectUri,
		State:       "",
		CreatedAt:   time.Unix(data.CreatedAt, 0),
		UserData:    data.Extra,
	}

	if data.Scope != nil {
		authorize.Scope = *data.Scope
	}

	if data.State != nil {
		authorize.State = *data.State
	}

	c, err := s.GetClient(cid)
	if err != nil {
		return nil, err
	}

	if authorize.ExpireAt().Before(time.Now()) {
		return nil, errors.New(fmt.Sprintf("Token expired at %s.", authorize.ExpireAt().String()))
	}

	authorize.Client = c
	return &authorize, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *Storage) RemoveAuthorize(code string) (err error) {

	if _, err = s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE code=?", s.db.TableMapper.Obj2Table("oauth_authorize")), code); err != nil {
		return err
	}

	if err = s.RemoveExpireAtData(code); err != nil {
		return err
	}

	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *Storage) SaveAccess(data *osin.AccessData) (err error) {

	prev := ""
	authorizeData := &osin.AuthorizeData{}

	if data.AccessData != nil {
		prev = data.AccessData.AccessToken
	}

	if data.AuthorizeData != nil {
		authorizeData = data.AuthorizeData
	}

	sess := s.db.NewSession()
	defer sess.Close()

	err = sess.Begin()

	if err != nil {
		return err
	}

	if data.RefreshToken != "" {

		if err := s.saveRefresh(sess, data.RefreshToken, data.AccessToken); err != nil {
			return err
		}
	}

	if data.Client == nil {
		return errors.New("data.Client must not be nil")
	}

	_, err = sess.Exec(fmt.Sprintf(`INSERT INTO %s 
		(client, authorize, previous, access_token, refresh_token, expires_in, scope, redirect_uri, created_at, extra) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.db.TableMapper.Obj2Table("oauth_access")),
		data.Client.GetId(), authorizeData.Code, prev, data.AccessToken,
		data.RefreshToken, data.ExpiresIn, data.Scope, data.RedirectUri,
		data.CreatedAt.Unix(), data.Client.GetUserData())

	if err != nil {

		if rbe := sess.Rollback(); rbe != nil {
			return rbe
		}

		return err
	}

	if err = s.AddExpireAtData(data.AccessToken, data.ExpireAt()); err != nil {
		return err
	}

	if err = sess.Commit(); err != nil {
		return err
	}

	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadAccess(code string) (*osin.AccessData, error) {

	var extra, cid, prevAccessToken, authorizeCode string
	var result osin.AccessData

	var access OauthAccess

	ok, err := s.db.Table(&access).Where("access_token=?", code).Get(&access)

	if !ok {
		return nil, osin.ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	cid = access.Client
	result.AccessToken = access.AccessToken

	if access.Previous != nil {
		prevAccessToken = *access.Previous
	}

	if access.RefreshToken != nil {
		result.RefreshToken = *access.RefreshToken
	}

	result.ExpiresIn = int32(access.ExpiresIn)

	result.Scope = ""
	if access.Scope != nil {
		result.Scope = *access.Scope
	}

	result.RedirectUri = access.RedirectUri
	result.CreatedAt = time.Unix(access.CreatedAt, 0)

	extra = ""
	if access.Extra != nil {
		extra = *access.Extra
	}

	result.UserData = extra
	client, err := s.GetClient(cid)

	if err != nil {
		return nil, err
	}

	result.Client = client
	result.AuthorizeData, _ = s.LoadAuthorize(authorizeCode)
	prevAccess, _ := s.LoadAccess(prevAccessToken)
	result.AccessData = prevAccess
	return &result, nil
}

// RemoveAccess revokes or deletes an AccessData.
func (s *Storage) RemoveAccess(code string) (err error) {

	if _, err = s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE access_token=?", s.db.TableMapper.Obj2Table("oauth_access")), code); err != nil {
		return err
	}

	if err = s.RemoveExpireAtData(code); err != nil {
		return err
	}

	return nil
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadRefresh(code string) (*osin.AccessData, error) {

	refresh := &OauthRefresh{}
	ok, err := s.db.Sql(fmt.Sprintf("SELECT access FROM %s WHERE token=?", s.db.TableMapper.Obj2Table("oauth_refresh")), code).Get(refresh)

	if !ok {
		return nil, osin.ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	return s.LoadAccess(refresh.Access)
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *Storage) RemoveRefresh(code string) error {

	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE token=?", s.db.TableMapper.Obj2Table("oauth_refresh")), code)

	if err != nil {
		return err
	}

	return nil
}

// CreateClientWithInformation Makes easy to create a osin.DefaultClient
func (s *Storage) CreateClientWithInformation(id string, secret string, redirectURI string, userData interface{}) osin.Client {
	return &osin.DefaultClient{
		Id:          id,
		Secret:      secret,
		RedirectUri: redirectURI,
		UserData:    userData,
	}
}

func (s *Storage) saveRefresh(tx *xorm.Session, refresh, access string) (err error) {

	_, err = tx.Exec(fmt.Sprintf(
		"INSERT INTO %s ( token, access) VALUES (?, ?)", s.db.TableMapper.Obj2Table("oauth_refresh")),
		refresh, access)

	if err != nil {
		if rbe := tx.Rollback(); rbe != nil {
			return rbe
		}
		return err
	}

	return nil
}

// AddExpireAtData add info in expires table
func (s *Storage) AddExpireAtData(code string, expireAt time.Time) error {

	if _, err := s.db.Exec(
		fmt.Sprintf("INSERT INTO %s (id, token, expires_at) VALUES(?, ?, ?)", s.db.TableMapper.Obj2Table("oauth_expires")),
		bson.NewObjectId().Hex(),
		code,
		expireAt.Unix(),
	); err != nil {
		return err
	}

	return nil
}

// RemoveExpireAtData remove info in expires table
func (s *Storage) RemoveExpireAtData(code string) error {

	_, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM %s WHERE token=?", s.db.TableMapper.Obj2Table("oauth_expires")),
		code,
	)

	return err
}

func SHA256(sources ...string) string {

	hash := sha256.New()

	for _, source := range sources {
		hash.Write([]byte(source))
	}

	md := hash.Sum(nil)
	return hex.EncodeToString(md)
}
