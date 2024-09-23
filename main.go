package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"text/template"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	protoAuth "github.com/logeshwarann-dev/auth-service/proto"
	protoTask "github.com/logeshwarann-dev/task-service/proto"
	"google.golang.org/grpc"
)

const (
	authServiceAddress = "auth-service:50051"
	taskServiceAddress = "task-service:50052"
	secretKey          = "bit$PIl@ni2023" // Replace with your actual secret key
)

var (
	authClient protoAuth.AuthServiceClient
	taskClient protoTask.TaskServiceClient
	tmpl       *template.Template
)

func init() {
	// Initialize gRPC clients
	authConn, err := grpc.Dial(authServiceAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to auth service: %v", err)
	}
	authClient = protoAuth.NewAuthServiceClient(authConn)

	taskConn, err := grpc.Dial(taskServiceAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to task service: %v", err)
	}
	taskClient = protoTask.NewTaskServiceClient(taskConn)

	// Parse HTML templates
	tmpl = template.Must(template.ParseGlob("html/*.html"))
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/register", registerHandler)
	r.HandleFunc("/tasks", tasksHandler)
	r.HandleFunc("/tasks/add", tasksHandler).Methods(http.MethodPost)
	r.HandleFunc("/tasks/update", updateTaskHandler).Methods(http.MethodPost)

	// Static file serving (CSS)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	http.Handle("/", r)

	log.Println("Frontend service started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if err := tmpl.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		req := &protoAuth.LoginRequest{Username: username, Password: password}
		resp, err := authClient.Login(context.Background(), req)
		if err != nil {
			http.Error(w, "Login failed: "+err.Error(), http.StatusUnauthorized)
			http.Redirect(w, r, "/login?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}

		// Store token in session or cookie for authenticated requests
		http.SetCookie(w, &http.Cookie{
			Name:  "auth_token",
			Value: resp.Token,
			Path:  "/",
		})

		http.Redirect(w, r, "/tasks", http.StatusSeeOther)
		return
	}

	errorMsg := r.URL.Query().Get("error")
	if err := tmpl.ExecuteTemplate(w, "login.html", struct{ Error string }{Error: errorMsg}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// logoutHandler clears the authentication token cookie and redirects to the login page.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "auth_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Set to -1 to delete the cookie
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		req := &protoAuth.RegisterRequest{Username: username, Password: password}
		_, err := authClient.Register(context.Background(), req)
		if err != nil {
			http.Error(w, "Registration failed", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "register.html", nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func tasksHandler(w http.ResponseWriter, r *http.Request) {
	var newTask *protoTask.Task
	if r.Method == http.MethodPost {
		var err error
		newTask, err = createTask(r)
		if err != nil {
			http.Error(w, "Failed to create task", http.StatusInternalServerError)
			return
		}
	}

	// Retrieve tasks and display them
	tasks, err := fetchTasks(r)
	if err != nil {
		tasks = []protoTask.Task{}
	}

	// Add the newly created task to the list of tasks
	if newTask != nil {
		tasks = append(tasks, protoTask.Task{
			TaskId: newTask.TaskId,
			Title:  newTask.Title,
			Done:   newTask.Done,
		})
	}

	if err := tmpl.ExecuteTemplate(w, "tasks.html", struct{ Tasks []protoTask.Task }{Tasks: tasks}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Update task handler function
func updateTaskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		taskID := r.FormValue("task_id")
		title := r.FormValue("title")
		done := r.FormValue("done") == "on"

		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		tokenStr := cookie.Value
		_, err = parseToken(tokenStr)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		req := &protoTask.UpdateTaskRequest{
			TaskId: taskID,
			Title:  title,
			Done:   done,
		}
		_, err = taskClient.UpdateTask(context.Background(), req)
		if err != nil {
			http.Error(w, "Failed to update task", http.StatusInternalServerError)
			return
		}

		// Fetch the updated tasks list
		tasks, err := fetchTasks(r)
		if err != nil {
			tasks = []protoTask.Task{}
		}
		// Respond with the updated tasks list
		if err := tmpl.ExecuteTemplate(w, "tasks.html", struct{ Tasks []protoTask.Task }{Tasks: tasks}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func createTask(r *http.Request) (*protoTask.Task, error) {
	title := r.FormValue("title")
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return nil, fmt.Errorf("authentication required")
	}

	tokenStr := cookie.Value
	claims, err := parseToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	userID := claims["user_id"].(string)

	req := &protoTask.AddTaskRequest{UserId: userID, Title: title}
	resp, err := taskClient.AddTask(context.Background(), req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("failed to add task")
	}

	// Return the newly created task
	return &protoTask.Task{
		TaskId: resp.TaskId,
		Title:  title,
		Done:   false,
	}, nil
}

func fetchTasks(r *http.Request) ([]protoTask.Task, error) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return nil, fmt.Errorf("authentication required")
	}

	tokenStr := cookie.Value
	claims, err := parseToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, fmt.Errorf("user ID not found in token")
	}

	req := &protoTask.ListTasksRequest{UserId: userID}
	resp, err := taskClient.ListTasks(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tasks: %v", err)
	}

	// Convert []*protoTask.Task to []protoTask.Task
	var tasks []protoTask.Task
	for _, t := range resp.Tasks {
		tasks = append(tasks, protoTask.Task{
			TaskId: t.TaskId,
			Title:  t.Title,
			Done:   t.Done,
		})
	}

	return tasks, nil
}

func parseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

type Task struct {
	TaskID string
	Title  string
	Done   bool
}
