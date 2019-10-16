// step 1:
// go get "golang.org/x/oauth2" "google.golang.org/api/oauth2/v2"
package main

// step 2:
// import them, and auth2/v2 should be given a different name to avoid namespace clashing
// for example: auth "google.golang.org/api/oauth2/v2"
// the above package contains scope url constant for getting user info such as email address etc.
import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"text/template"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	auth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

// step 3: initialize the variable which will be storing config for performing 3-legged oauth2 authorization process
var (
	googleOauthConfig *oauth2.Config
	oauthStateString  string = "random string"
)

func init() {
	// the json file can be obtained from google cloud developers console
	b, err := ioutil.ReadFile("client-cred.json")
	if err != nil {
		log.Fatalln(err)
	}
	// step 4: use convenience function called ConfigFromJSON to convert json file to struct
	googleOauthConfig, err = google.ConfigFromJSON(b, auth.UserinfoEmailScope)
	if err != nil {
		log.Fatalln(err)
	}
	// step 5: add the profile scope as well
	googleOauthConfig.Scopes = append(googleOauthConfig.Scopes, "https://www.googleapis.com/auth/userinfo.profile")
}

func main() {
	// step 6: define handlers for each endpoint, one for login, one for callback and one for index
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleRedirectAndShowUserInfo)
	http.ListenAndServe(":8080", http.DefaultServeMux)
}

// handleIndex displays the Google Log In link
// user clicks link to initiate the oauth2 authorization grant process
func handleIndex(w http.ResponseWriter, r *http.Request) {
	// render template index.html
	tmpl := template.Must(template.ParseFiles("index.html"))
	tmpl.Execute(w, nil)
}

// handleGoogleLogin redirects user to google oauth2 endpoint to obtain authorization code
// authorization code obtained from authorization server shall then exchanged for a token
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// build authorization server endpoint url using state string
	log.Println(googleOauthConfig)
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	// redirect user to authorization server endpoint
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// handleGoogleRedirectAndShowUserInfo exchanges authorization code sent from authorization server
// and obtains token to retreive user info from the appropriate resource endpoint
func handleRedirectAndShowUserInfo(w http.ResponseWriter, r *http.Request) {
	// create context
	ctx := context.Background()
	// check if the state string returned from oauth2 endpoint is the same one we sent
	if r.FormValue("state") != oauthStateString {
		log.Fatalln("invalid auth state")
	}
	// exchange the authorization code for the token
	token, err := googleOauthConfig.Exchange(ctx, r.FormValue("code"))
	if err != nil {
		log.Fatalln(err)
	}
	// get user info
	user, err := getUserInfo(ctx, token)
	if err != nil {
		log.Fatalln(err)
	}
	// render template index.html with user info
	tmpl := template.Must(template.ParseFiles("index.html"))
	tmpl.Execute(w, user)
}

func getUserInfo(ctx context.Context, token *oauth2.Token) (user *auth.Userinfoplus, err error) {
	// create new auth service
	authService, err := auth.NewService(ctx, option.WithTokenSource(googleOauthConfig.TokenSource(ctx, token)))
	if err != nil {
		return
	}
	// get user info
	user, err = authService.Userinfo.V2.Me.Get().Do()
	if err != nil {
		return
	}
	return
}
