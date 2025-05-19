#include "../Zend/zend_compile.h"
#include "../Zend/zend_execute.h"
#include "zend.h"
#include "zend_modules.h"

#include <unistd.h>
#include <string.h> /* For the real memset prototype.  */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <time.h>

typedef unsigned long long u64;

int value_diff_changes(char *var1, char *var2);
void value_diff_report(char *var1, char *var2, int bitmapLoc);
void var_diff_report(char *var1, int bitmapLoc, int var_type);
void dbg_printf(const char *fmt, ...);

#define DEBUG_MODE 0

#if DEBUG_MODE
#define debug_print(xval) \
    do                    \
    {                     \
        dbg_printf xval;  \
    } while (0)
#else
#define debug_print(fmt, ...)
#endif

/***** END new for HTTP direct ********/

#define MAP_SIZE 65536
#define TRACE_SIZE 128 * (1024 * 1024) // X * megabytes

#define SHM_ENV_VAR "__AFL_SHM_ID"

#define STDIN_FILENO 0

static int last_op = 0;
static int cur_op = 0;

static int MAX_CMDLINE_LEN = 128 * 1024;

static unsigned char *afl_area_ptr = NULL;

unsigned int afl_forksrv_pid = 0;
static unsigned char afl_fork_child;

#define FORKSRV_FD 198
#define TSL_FD (FORKSRV_FD - 1)

#define MAX_VARIABLES 1024
char *variables[3][MAX_VARIABLES];
unsigned char variables_used[3][MAX_VARIABLES];
int variables_ptr[3] = {0, 0, 0};

char *traceout_fn, *traceout_path;

int nextVar2_is_a_var = -1;
bool wc_extra_instr = true;

static bool start_tracing = false;

static char *env_vars[2] = {"HTTP_COOKIE", "QUERY_STRING"};
char *login_cookie = NULL, *mandatory_cookie = NULL, *preset_cookie = NULL;
char *witcher_print_op = NULL;

char *main_filename;
char session_id[40];
int saved_session_size = 0;

int trace[TRACE_SIZE];
int trace_index = 0;

int pipefds[2];

int top_pid = 0;

struct FileInfo
{
    u64 node_id;
    char filename[100];
    struct LineInfo *lines;
    struct FileInfo *next;
};

struct LineInfo
{
    u64 node_id;
    u64 lineno;
    u64 dist;
    char type;
    char varname[50];
    struct LineInfo *next;
};

static u64 last_dist_node_id = 0;

static struct FileInfo *dist_info = NULL;
static struct FileInfo *taint_info = NULL;

static char funx_check_filename[100];
static u64 funx_check_lineno = 0;
static char jmpx_check_filename[100];
static u64 jmpx_check_lineno = 0;

static const zend_uchar zend_jmpx[] = {
    ZEND_JMP,      // Unconditional jump
    ZEND_JMPZ,     // Jump if zero
    ZEND_JMPNZ,    // Jump if not zero
    ZEND_JMPZNZ,   // Jump to one address if zero, else jump to another address
    ZEND_JMPZ_EX,  // Jump if zero with extra check
    ZEND_JMPNZ_EX, // Jump if not zero with extra check
};

static const zend_uchar zend_funx[] = {
    ZEND_DO_FCALL,         // Execute function call
    ZEND_DO_ICALL,         // Execute indirect call
    ZEND_DO_UCALL,         // Execute unresolved call
    ZEND_DO_FCALL_BY_NAME, // Execute function call by name
    ZEND_CALL_TRAMPOLINE,  // Call trampoline
    ZEND_FAST_CALL,        // Fast call
    ZEND_RETURN,           // Return
    ZEND_RETURN_BY_REF,    // Return by reference
    ZEND_FAST_RET,         // Fast return
};

static const zend_uchar zend_include_or_eval[] = {
    ZEND_INCLUDE_OR_EVAL, // Execute include or eval statement
};

static const zend_uchar zend_assign[] = {
    ZEND_ASSIGN, // Execute include or eval statement
};

// Read CSV file and parse it into a dictionary
void read_csv(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        return;
    }

    char line[256];
    struct FileInfo *dist_head = NULL;
    struct FileInfo *dist_current = NULL;
    struct FileInfo *taint_head = NULL;
    struct FileInfo *taint_current = NULL;

    fgets(line, sizeof(line), file); // Skip the first line
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = '\x00';
        char *id_str = strtok(line, "\t");
        char *type_str = strtok(NULL, "\t");
        char *lineno_str = strtok(NULL, "\t");
        char *value_str = strtok(NULL, "\t");

        u64 node_id = strtoull(id_str, NULL, 10);
        u64 lineno = strtoull(lineno_str, NULL, 10);
        u64 dist = (type_str[0] == 'd' || type_str[0] == 'e') ? strtoull(value_str, NULL, 10) : 0;

        if (type_str[0] == 'f')
        {
            struct FileInfo *file_info = (struct FileInfo *)malloc(sizeof(struct FileInfo));
            struct FileInfo *file_info_2 = (struct FileInfo *)malloc(sizeof(struct FileInfo));
            file_info->node_id = node_id;
            strncpy(file_info->filename, value_str, sizeof(file_info->filename));
            file_info->lines = NULL;
            file_info->next = NULL;
            memcpy(file_info_2, file_info, sizeof(struct FileInfo));

            if (dist_current == NULL)
            {
                dist_head = file_info;
                dist_current = file_info;
                taint_head = file_info_2;
                taint_current = file_info_2;
            }
            else
            {
                dist_current->next = file_info;
                dist_current = file_info;
                taint_current->next = file_info_2;
                taint_current = file_info_2;
            }
        }
        else if (type_str[0] == 'd' || type_str[0] == 'e')
        {
            struct LineInfo *dist_line_info = (struct LineInfo *)malloc(sizeof(struct LineInfo));
            dist_line_info->node_id = node_id;
            dist_line_info->lineno = lineno;
            dist_line_info->dist = dist;
            dist_line_info->type = type_str[0];
            dist_line_info->next = NULL;

            if (dist_current != NULL)
            {
                if (dist_current->lines == NULL)
                {
                    dist_current->lines = dist_line_info;
                }
                else
                {
                    struct LineInfo *dist_current_line = dist_current->lines;
                    while (dist_current_line->next != NULL)
                    {
                        dist_current_line = dist_current_line->next;
                    }
                    dist_current_line->next = dist_line_info;
                }
            }
        }
        else if (type_str[0] == 't')
        {
            struct LineInfo *taint_line_info = (struct LineInfo *)malloc(sizeof(struct LineInfo));
            taint_line_info->node_id = node_id;
            taint_line_info->lineno = lineno;
            taint_line_info->dist = dist;
            taint_line_info->type = type_str[0];
            strncpy(taint_line_info->varname, value_str, sizeof(taint_line_info->varname));
            taint_line_info->next = NULL;

            if (taint_current != NULL)
            {
                if (taint_current->lines == NULL)
                {
                    taint_current->lines = taint_line_info;
                }
                else
                {
                    struct LineInfo *taint_current_line = taint_current->lines;
                    while (taint_current_line->next != NULL)
                    {
                        taint_current_line = taint_current_line->next;
                    }
                    taint_current_line->next = taint_line_info;
                }
            }
        }
    }
    fclose(file);
    dist_info = dist_head;
    taint_info = taint_head;
}

// Write the dictionary to a CSV file to update
void update_csv(const char *filename)
{
    FILE *file = fopen(filename, "w");
    if (!file)
    {
        return;
    }

    if (flock(fileno(file), LOCK_EX) == -1)
    {
        fclose(file);
        return; // Return if file is already locked by another process
    }

    fprintf(file, "id\ttype\tlineno\tvalue\n");
    struct FileInfo *current_file_dist = dist_info;
    struct FileInfo *current_file_taint = taint_info;
    while (current_file_dist != NULL)
    {
        fprintf(file, "%lld\tf\t0\t%s\n", current_file_dist->node_id, current_file_dist->filename);
        struct LineInfo *current_line_dist = current_file_dist->lines;
        struct LineInfo *current_line_taint = current_file_taint->lines;
        while (current_line_taint != NULL)
        {
            fprintf(file, "%lld\t%c\t%lld\t%s\n", current_line_taint->node_id, current_line_taint->type, current_line_taint->lineno, current_line_taint->varname);
            current_line_taint = current_line_taint->next;
        }
        while (current_line_dist != NULL)
        {
            fprintf(file, "%lld\t%c\t%lld\t%lld\n", current_line_dist->node_id, current_line_dist->type, current_line_dist->lineno, current_line_dist->dist);
            current_line_dist = current_line_dist->next;
        }

        current_file_dist = current_file_dist->next;
        current_file_taint = current_file_taint->next;
    }

    flock(fileno(file), LOCK_UN); // Release the lock
    fclose(file);
}

// Free the memory used by the dictionary
void free_memory(struct FileInfo *head)
{
    while (head != NULL)
    {
        struct FileInfo *temp_file = head;
        head = head->next;

        struct LineInfo *current_line = temp_file->lines;
        while (current_line != NULL)
        {
            struct LineInfo *temp_line = current_line;
            current_line = current_line->next;
            free(temp_line);
        }

        free(temp_file);
    }
}

void dbg_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

/**
 * Mostly taken from the afl_forkserver code provided with AFL
 * Injects a fork server into php_cgi to speed things up
 */
static void afl_forkserver()
{

    static unsigned char tmp[4];

    if (!afl_area_ptr)
        return;
    if (write(FORKSRV_FD + 1, tmp, 4) != 4)
        return;

    afl_forksrv_pid = getpid();

    /* All right, let's await orders... */
    int claunch_cnt = 0;
    while (1)
    {

        pid_t child_pid = -1;
        int status, t_fd[2];

        /* Whoops, parent dead? */
        if (read(FORKSRV_FD, tmp, 4) != 4)
            exit(2);

        /* Establish a channel with child to grab translation commands. We'll
           read from t_fd[0], child will write to TSL_FD. */
        if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0)
            exit(3);
        close(t_fd[1]);
        claunch_cnt++;
        child_pid = fork();

        fflush(stdout);
        if (child_pid < 0)
            exit(4);

        if (!child_pid)
        { // child_pid == 0, i.e., in child

            /* Child process. Close descriptors and run free. */
            debug_print(("\t\t\tlaunch cnt = %d Child pid == %d, but current pid = %d\n", claunch_cnt, child_pid, getpid()));
            fflush(stdout);
            afl_fork_child = 1;
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            close(t_fd[0]);
            return;
        }

        /* Parent. */

        close(TSL_FD);

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4)
        {
            debug_print(("\t\tExiting Parent %d with 5\n", child_pid));
            exit(5);
        }

        /* Get and relay exit status to parent. */
        int waitedpid = waitpid(child_pid, &status, 0);
        if (waitedpid < 0)
        {
            printf("\t\tExiting Parent %d with 6\n", child_pid);
            exit(6);
        }

        if (write(FORKSRV_FD + 1, &status, 4) != 4)
        {
            exit(7);
        }
    }
}

void load_variables(char *str, int var_type)
{
    char *tostr = strdup(str);
    char *end_str;
    char *token = strtok_r(tostr, "&", &end_str);

    while (token != NULL)
    {
        char *end_token;
        char *dup_token = strdup(token);
        char *subtok = strtok_r(dup_token, "=", &end_token);

        if (subtok != NULL && variables_ptr[var_type] < MAX_VARIABLES)
        {
            char *first_part = strdup(subtok);
            subtok = strtok_r(NULL, "=", &end_token);
            int len = strlen(first_part);
            if (len > 2)
            {
                bool unique = true;
                for (int i = 0; i < variables_ptr[var_type]; i++)
                {
                    if (strcmp(first_part, variables[var_type][i]) == 0)
                    {
                        unique = false;
                        break;
                    }
                }
                if (unique)
                {
                    int cur_ptr = variables_ptr[var_type];
                    variables[var_type][cur_ptr] = (char *)malloc(len + 1);
                    strncpy(variables[var_type][cur_ptr], first_part, len);
                    variables[var_type][cur_ptr][len] = '\x00';
                    variables_used[var_type][cur_ptr] = 0;
                    variables_ptr[var_type]++;
                }
            }
            token = strtok_r(NULL, "&", &end_str);
        }
        else
        {
            break;
        }
    }
}

char *replace_char(char *str, char find, char replace)
{
    char *current_pos = strchr(str, find);
    while (current_pos)
    {
        *current_pos = replace;
        current_pos = strchr(current_pos, find);
    }
    return str;
}

char *format_to_json(char *str)
{

    char *tostr = strdup(str);
    char *outstr;
    outstr = (char *)malloc(strlen(str) + 1024);
    char *end_str;
    char *token = strtok_r(tostr, "&", &end_str);
    outstr = strcat(outstr, "{");

    while (token != NULL)
    {
        char jsonEleOut[strlen(str) + 7];
        char *end_token;
        char *dup_token = strdup(token);
        char *first_part = strtok_r(dup_token, "=", &end_token);
        char *sec_part = strtok_r(NULL, "=", &end_token);
        if (sec_part)
        {
            sprintf(jsonEleOut, "\"%s\":\"%s\",", first_part, sec_part);
        }
        else
        {
            sprintf(jsonEleOut, "\"%s\":\"\",", first_part);
        }
        outstr = strcat(outstr, jsonEleOut);
        token = strtok_r(NULL, "&", &end_str);
    }

    outstr[strlen(outstr) - 1] = '}';
    outstr[strlen(outstr)] = '\x00';

    return outstr;
}

/**
 * sets up the cgi environment for a cgi request
 */
void prefork_cgi_setup()
{
    debug_print(("[\e[32mWitcher\e[0m] Starting SETUP_CGI_ENV  \n"));
    char *tmp = getenv("DOCUMENT_ROOT");
    if (!tmp)
    {
        setenv("DOCUMENT_ROOT", "/app", 1); // might be important if your cgi read/writes there
    }
    setenv("HTTP_REDIRECT_STATUS", "1", 1);

    setenv("HTTP_ACCEPT", "*/*", 1);
    setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);

    setenv("PATH", "/usr/bin:/tmp:/app", 1); // HTTP URL PATH
    tmp = getenv("REQUEST_METHOD");
    if (!tmp)
    {
        setenv("REQUEST_METHOD", "POST", 1); // Usually GET or POST
    }
    setenv("REMOTE_ADDR", "127.0.0.1", 1);

    setenv("CONTENT_TYPE", "application/x-www-form-urlencoded", 1);
    setenv("REQUEST_URI", "SCRIPT", 1);
    login_cookie = getenv("LOGIN_COOKIE");

    char *preset_cookie = (char *)malloc(MAX_CMDLINE_LEN);
    memset(preset_cookie, 0, MAX_CMDLINE_LEN);

    if (login_cookie)
    {
        strcat(preset_cookie, login_cookie);
        setenv(env_vars[0], login_cookie, 1);
        if (!strchr(login_cookie, ';'))
        {
            strcat(login_cookie, ";");
        }
        debug_print(("[\e[32mWitcher\e[0m] LOGIN COOKIE %s\n", login_cookie));
        char *name = strtok(login_cookie, ";=");
        while (name != NULL)
        {
            char *value = strtok(NULL, ";=");
            if (value != NULL)
            {
                debug_print(("\t%s==>%s\n", name, value)); // printing each token
            }
            else
            {
                debug_print(("\t%s==> NADA \n", name)); // printing each token
            }

            if (value != NULL)
            {
                int thelen = strlen(value);
                if (thelen >= 24 && thelen <= 32)
                {
                    debug_print(("[\e[32mWitcher\e[0m] session_id = %s, len=%d\n", value, thelen));
                    strcpy(session_id, value);
                    char filename[64];
                    char sess_fn[64];
                    char command_tmp[96];
                    sprintf(sess_fn, "/tmp/sess_%s", value);
                    sprintf(command_tmp, "sudo chown wc:wc %s", sess_fn);
                    system(command_tmp);
                    setenv("SESSION_FILENAME", sess_fn, 1);

                    sprintf(filename, "/tmp/save_%s", value);

                    // saved_session_size = fsize(filename);

                    debug_print(("\t[WC] SESSION ID = %s, saved session size = %d\n", filename, saved_session_size));
                    break;
                }
            }
            name = strtok(NULL, ";=");
        }
        debug_print(("[\e[32mWitcher\e[0m] LOGIN ::> %s\n", login_cookie));
    }
    mandatory_cookie = getenv("MANDATORY_COOKIE");
    if (mandatory_cookie && strlen(mandatory_cookie) > 0)
    {
        strcat(preset_cookie, "; ");
        strcat(preset_cookie, mandatory_cookie);
        debug_print(("[\e[32mWitcher\e[0m] MANDATORY COOKIE = %s\n", preset_cookie));
    }
    witcher_print_op = getenv("WITCHER_PRINT_OP");
}

void setup_cgi_env()
{

    // strict is set for the modified /bin/dash
#if DEBUG_MODE
    FILE *logfile = fopen("/tmp/wrapper.log", "a+");
    fprintf(logfile, "----Start----\n");
    // printf("starting\n");
#endif

    static int num_env_vars = sizeof(env_vars) / sizeof(char *);

    char in_buf[MAX_CMDLINE_LEN];
    memset(in_buf, 0, MAX_CMDLINE_LEN);
    size_t bytes_read = read(0, in_buf, MAX_CMDLINE_LEN - 2);

    int zerocnt = 0;
    for (int cnt = 0; cnt < MAX_CMDLINE_LEN; cnt++)
    {
        if (in_buf[cnt] == 0)
        {
            zerocnt++;
        }
        if (zerocnt == 3)
        {
            break;
        }
    }

    pipe(pipefds);

    dup2(pipefds[0], STDIN_FILENO);
    // close(STDIN_FILENO);

    int real_content_length = 0;
    char *saved_ptr = (char *)malloc(MAX_CMDLINE_LEN);
    char *ptr = in_buf;
    int rc = 0;
    char *cwd;
    int errnum;
    // struct passwd *p = getpwuid(getuid());  // Check for NULL!
    long size = pathconf(".", _PC_PATH_MAX);
    char *dirbuf = (char *)malloc((size_t)size);
    size_t bytes_used = 0;

    // loop through the strings read via stdin and break at each \x00
    // Cookies, Query String, Post (via re-writting to stdin)
    char *cookie = (char *)malloc(MAX_CMDLINE_LEN);
    memset(cookie, 0, MAX_CMDLINE_LEN);
    if (preset_cookie)
    {
        strcat(cookie, preset_cookie);
    }
    if (getenv("HTTP_COOKIE"))
    {
        if (strlen(cookie) > 0)
        {
            strcat(cookie, "; ");
        }
        strcat(cookie, getenv("HTTP_COOKIE"));
    }

    setenv(env_vars[0], cookie, 1);
    char *post_data = (char *)malloc(MAX_CMDLINE_LEN);
    memset(post_data, 0, MAX_CMDLINE_LEN);
    char *query_string = (char *)malloc(MAX_CMDLINE_LEN);
    memset(query_string, 0, MAX_CMDLINE_LEN);

    setenv(env_vars[1], query_string, 1);

    while (!*ptr)
    {
        bytes_used++;
        ptr++;
        rc++;
    }
    while (*ptr || bytes_used < bytes_read)
    {
        memcpy(saved_ptr, ptr, strlen(ptr) + 1);
        if (rc < 3)
        {
            load_variables(saved_ptr, rc);
        }
        if (rc < num_env_vars)
        {

            if (rc == 0)
            {
                strcat(cookie, "; ");
                strcat(cookie, saved_ptr);
                cookie = replace_char(cookie, '&', ';');
                setenv(env_vars[rc], cookie, 1);
            }
            else if (rc == 1)
            {
                strcat(query_string, "&");
                strcat(query_string, saved_ptr);

                setenv(env_vars[rc], query_string, 1);
            }
            else
            {

                setenv(env_vars[rc], saved_ptr, 1);
            }

            if (afl_area_ptr != NULL)
            {
                afl_area_ptr[0xffdd] = 1;
            }
        }
        else if (rc == num_env_vars)
        {
            char *json = getenv("DO_JSON");
            if (json)
            {
                saved_ptr = format_to_json(saved_ptr);
                debug_print(("\e[32m\tDONE JSON=%s\e[0m\n", saved_ptr));
            }

            real_content_length = write(pipefds[1], saved_ptr, strlen(saved_ptr));
            write(pipefds[1], "\n", 1);

            // debug_print(("\tReading from %d and writing %d bytes to %d \n", real_content_length, pipefds[0], pipefds[1]));
            // debug_print(("\t%-15s = \033[33m%s\033[0m \n", "POST", saved_ptr));

            char snum[20];
            sprintf(snum, "%d", real_content_length);
            memcpy(post_data, saved_ptr, strlen(saved_ptr) + 1);
            setenv("E", saved_ptr, 1);
            setenv("CONTENT_LENGTH", snum, 1);
        }

        rc++;
        while (*ptr)
        {
            ptr++;
            bytes_used++;
        }
        ptr++;
        bytes_used++;
    }
    debug_print(("[\e[32mWitcher\e[0m] %lib read / %lib used \n", bytes_read, bytes_used));
    if (afl_area_ptr != NULL)
    {
        afl_area_ptr[0xffdd] = 1;
    }
    if (cookie)
    {
        debug_print(("\t%-14s = \e[33m %s\e[0m\n", "COOKIES", cookie));
    }
    if (query_string)
    {
        debug_print(("\t%-14s = \e[33m %s\e[0m\n", "QUERY_STRING", query_string));
    }
    if (post_data)
    {
        debug_print(("\t%-9s (%s) = \e[33m %s\e[0m\n", "POST_DATA", getenv("CONTENT_LENGTH"), post_data));
    }
    debug_print(("\n"));

    free(saved_ptr);
    free(cookie);
    free(query_string);
    free(post_data);

    close(pipefds[0]);
    close(pipefds[1]);
#if DEBUG_MODE
    fclose(logfile);
#endif

    fflush(stderr);
}
/************************************************************************************************/
/********************************** HTTP direct **************************************************/
/************************************************************************************************/
void afl_error_handler(int nSignum)
{
    FILE *elog = fopen("/tmp/witcher.log", "a+");
    if (elog)
    {
        fprintf(elog, "\033[36m[Witcher] detected error in child but AFL_META_INFO_ID is not set. !!!\033[0m\n");
        fclose(elog);
    }
}

/************************************************************************************************/
/********************************** END HTTP direct **************************************************/
/************************************************************************************************/

unsigned char *cgi_get_shm_mem(char *ch_shm_id)
{
    char *id_str;
    int shm_id;

    if (afl_area_ptr == NULL)
    {
        id_str = getenv(SHM_ENV_VAR);
        if (id_str)
        {
            shm_id = atoi(id_str);
            afl_area_ptr = shmat(shm_id, NULL, 0);
        }
        else
        {
            afl_area_ptr = malloc(MAP_SIZE + 16);
        }
    }
    return afl_area_ptr;
}

/**
 * The witcher init, is needed at the start of the script and is only executed once per child
 * it sets up the tracing enviornment
 */
void witcher_cgi_trace_init(char *ch_shm_id)
{
    debug_print(("[\e[32mWitcher\e[0m] in Witcher trace\n\t\e[34mSCRIPT_FILENAME=%s\n\t\e[34mAFL_PRELOAD=%s\n\t\e[34mLD_LIBRARY_PATH=%s\e[0m\n", getenv("SCRIPT_FILENAME"), getenv("AFL_PRELOAD"), getenv("LD_LIBRARY_PATH"), getenv("LOGIN_COOKIE")));

    if (getenv("WC_INSTRUMENTATION"))
    { 
        start_tracing = true;
        debug_print(("[Witcher] \e[32m WC INSTUMENTATION ENABLED \e[0m "));
    }
    else
    {
        debug_print(("[Witcher] WC INSTUMENTATION DISABLED "));
    }

    if (getenv("NO_WC_EXTRA"))
    {
        wc_extra_instr = false;
        debug_print((" WC Extra Instrumentation DISABLED \n"));
    }
    else
    {
        debug_print((" \e[32m WC Extra Instrumentation ENABLED \e[0m\n"));
    }
    top_pid = getpid();
    cgi_get_shm_mem(SHM_ENV_VAR);

    char *id_str = getenv(SHM_ENV_VAR);
    prefork_cgi_setup();
    if (id_str)
    {
        afl_forkserver();
        debug_print(("[\e[32mWitcher\e[0m] Returning with pid %d \n\n", getpid()));
    }
    // setup cgi must be after fork
    setup_cgi_env();

    // fflush(stdout);
}

void witcher_cgi_trace_finish()
{
    // find taints and write to file named with shm id
    if (last_dist_node_id != 0)
    {
        find_origins_for_node(last_dist_node_id);
        last_dist_node_id = 0;
    }

    start_tracing = false;
#if DEBUG_MODE
    if (witcher_print_op)
    {
        char logfn[50];
        sprintf(logfn, "/tmp/bitmap-%s.dat", witcher_print_op);
        FILE *tout_fp = fopen(logfn, "a+");
        setbuf(tout_fp, NULL);
        int cnt = 0;
        for (int x = 0; x < MAP_SIZE; x++)
        {
            if (afl_area_ptr[x] > 0)
            {
                cnt++;
            }
        }
        fprintf(tout_fp, "BitMap has %d  \n", cnt);

        for (int x = 0; x < MAP_SIZE; x++)
        {
            if (afl_area_ptr[x] > 0)
            {
                fprintf(tout_fp, "%04x ", x);
            }
        }
        fprintf(tout_fp, "\n");
        for (int x = 0; x < MAP_SIZE; x++)
        {
            if (afl_area_ptr[x] > 0)
            {
                fprintf(tout_fp, " %02x  ", afl_area_ptr[x]);
            }
        }
        fprintf(tout_fp, "\n");

        // fprintf(logfile2,"\tAFTER match=%d afl=%d \n", matchcnt, afl_area_ptr[bitmapLoc]);

        fclose(tout_fp);
    }
#endif
    cur_op = 0;
    last_op = 0;
    trace_index = 0;
    free_memory(dist_info);
    free_memory(taint_info);
}

void vld_start_trace()
{
    if (dist_info == NULL)
    {
        read_csv("/tmp/instr-info.csv");
    }
}

bool is_opcode_in_array(zend_uchar opcode, const zend_uchar opcodes[], size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        if (opcodes[i] == opcode)
        {
            return true;
        }
    }
    return false;
}

void find_origins_for_node(u64 node_id)
{
    FILE *file_in = fopen("/tmp/data_flow_origins.csv", "r");
    // Write to the file named with shm id
    char filename[32];
    sprintf(filename, "/tmp/origins-%s.csv", getenv(SHM_ENV_VAR));
    struct FileInfo *current_file = taint_info;
    struct LineInfo *current_line = NULL;

    if (file_in == NULL)
    {
        perror("Unable to open the file(s)");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file_in))
    {
        char *token = strtok(line, "\t");
        u64 current_id = strtoull(token, NULL, 10);

        if (current_id == node_id)
        {
            token = strtok(NULL, "\t");
            if (token != NULL)
            {
                FILE *file_clr = fopen(filename, "w");
                fclose(file_clr);
                char *value = strtok(token, ",");
                while (value != NULL)
                {
                    u64 ori_node_id = strtoull(value, NULL, 10);
                    // Find node with the same id in taint_info
                    current_file = taint_info;
                    bool found = false;
                    while (current_file != NULL && !found)
                    {
                        current_line = current_file->lines;
                        while (current_line != NULL)
                        {
                            if (current_line->node_id == ori_node_id)
                            {
                                FILE *file_out = fopen(filename, "a");
                                fprintf(file_out, "%s=&\n", current_line->varname);
                                fclose(file_out);
                                found = true;
                                break;
                            }
                            current_line = current_line->next;
                        }
                        current_file = current_file->next;
                    }
                    value = strtok(NULL, ",");
                }
            }
            break;
        }
    }

    fclose(file_in);
}

// Function to get the distance value based on the provided filename and lineno
struct LineInfo *get_info(const char *filename, u64 lineno, struct FileInfo *info)
{
    struct FileInfo *current_file = info;
    while (current_file != NULL)
    {
        if (strstr(filename, current_file->filename) != NULL)
        {
            struct LineInfo *current_line = current_file->lines;
            while (current_line != NULL && current_line->lineno <= lineno)
            {
                if (current_line->lineno == lineno)
                {
                    return current_line;
                }
                current_line = current_line->next;
            }
            return NULL;
        }
        current_file = current_file->next;
    }
    return NULL;
}

// Check if there is a critical node between the last and current line number
struct LineInfo *critical_between_last_and_cur_lineno(const char *filename, u64 last_lineno, u64 cur_lineno, struct FileInfo *info)
{
    struct FileInfo *current_file = info;
    while (current_file != NULL)
    {
        if (strstr(filename, current_file->filename) != NULL)
        {
            struct LineInfo *current_line = current_file->lines;
            while (current_line != NULL && current_line->lineno < cur_lineno)
            {
                if (current_line->lineno > last_lineno)
                {
                    return current_line;
                }
                current_line = current_line->next;
            }
            return NULL;
        }
        current_file = current_file->next;
    }
    return NULL;
}

void insert_into_info_list(const char *filename, u64 lineno, u64 insert_dist, struct FileInfo *dist_info, struct FileInfo *taint_info)
{
    // Find the file in the linked list
    struct FileInfo *current_file_dist = dist_info;
    struct FileInfo *current_file_taint = taint_info;
    srand(time(NULL));
    while (current_file_dist != NULL)
    {
        if (strstr(filename, current_file_dist->filename) != NULL)
        {
            struct LineInfo *current_line = current_file_dist->lines;
            struct LineInfo *parent_line = NULL;
            while (current_line != NULL && current_line->lineno <= lineno)
            {
                parent_line = current_line;
                current_line = current_line->next;
            }
            struct LineInfo *new_line = (struct LineInfo *)malloc(sizeof(struct LineInfo));
            new_line->node_id = rand() % MAP_SIZE;
            new_line->lineno = lineno;
            new_line->dist = insert_dist;
            new_line->type = 'd';
            new_line->next = current_line;
            if (parent_line == NULL)
            {
                current_file_dist->lines = new_line;
            }
            else
            {
                parent_line->next = new_line;
            }
            break;
        }
        current_file_dist = current_file_dist->next;
    }
    if (current_file_dist == NULL)
    {
        struct FileInfo *new_file = (struct FileInfo *)malloc(sizeof(struct FileInfo));

        new_file->node_id = rand() % MAP_SIZE;
        strncpy(new_file->filename, filename, sizeof(new_file->filename));
        new_file->lines = (struct LineInfo *)malloc(sizeof(struct LineInfo));
        new_file->lines->node_id = rand() % MAP_SIZE;
        new_file->lines->lineno = lineno;
        new_file->lines->dist = insert_dist;
        new_file->lines->next = NULL;
        new_file->next = dist_info;
        dist_info = new_file;

        // Sync taint info
        struct FileInfo *new_file2 = (struct FileInfo *)malloc(sizeof(struct FileInfo));
        new_file2->lines = NULL;
        new_file2->next = taint_info;
        taint_info = new_file2;
    }
    update_csv("/tmp/instr-info.csv");
}

void update_bitmap(struct LineInfo *cur_line_info, int bitmapLoc)
{
    bitmapLoc = (cur_line_info->node_id ^ bitmapLoc) % MAP_SIZE;
    afl_area_ptr[bitmapLoc]++;

    // Update distance
    if (cur_line_info->dist > 0)
    {
        memcpy(afl_area_ptr + MAP_SIZE, &(cur_line_info->dist), sizeof(u64));
        afl_area_ptr[MAP_SIZE + 8]++;
    }
}

void vld_external_trace(const char *op, const zend_op *opline, zend_execute_data *execute_data)
{
    // Get the current file name and line number
    const char *current_filename = zend_get_executed_filename();
    const u64 current_lineno = opline->lineno;

    if (start_tracing)
    {
        bool jmpx_found = false;
        bool funx_found = false;
        bool assign_found = false;
        int bitmapLoc = 0;
        u64 *cur_dist = (u64 *)(afl_area_ptr + MAP_SIZE);
        cur_op = (opline->lineno << 8) | opline->opcode;
        if (last_op != 0)
        {
            bitmapLoc = (cur_op ^ last_op) % MAP_SIZE;
        }
        if (is_opcode_in_array(opline->opcode, zend_jmpx, sizeof(zend_jmpx) / sizeof(zend_uchar)))
        {
            jmpx_found = true;
        }
        else if (is_opcode_in_array(opline->opcode, zend_funx, sizeof(zend_funx) / sizeof(zend_uchar)))
        {
            funx_found = true;
        }
        else if (is_opcode_in_array(opline->opcode, zend_include_or_eval, sizeof(zend_include_or_eval) / sizeof(zend_uchar)))
        {
            if (opline->extended_value == ZEND_EVAL)
            {
                funx_found = true;
            }
            else
            {
                jmpx_found = true;
            }
        }
        else if (is_opcode_in_array(opline->opcode, zend_assign, sizeof(zend_assign) / sizeof(zend_uchar)))
        {
            assign_found = true;
        }
        if (jmpx_found)
        {
            struct LineInfo *cur_line_info = get_info(current_filename, current_lineno, dist_info);
            if (cur_line_info != NULL)
            {
                last_dist_node_id = cur_line_info->node_id;
                if (*cur_dist > cur_line_info->dist)
                {
                    update_bitmap(cur_line_info, bitmapLoc);
                }
            }
        }
        else if (funx_found)
        {
            struct LineInfo *cur_line_info = get_info(current_filename, current_lineno, dist_info);
            if (cur_line_info != NULL)
            {
                last_dist_node_id = cur_line_info->node_id;
                if (*cur_dist > cur_line_info->dist)
                {
                    update_bitmap(cur_line_info, bitmapLoc);
                }
            }
            else
            {
                strncpy(funx_check_filename, current_filename, sizeof(funx_check_filename));
                funx_check_lineno = current_lineno;
            }
        }
        else if (assign_found)
        {
            struct LineInfo *cur_line_info = get_info(current_filename, current_lineno, taint_info);
            if (cur_line_info != NULL && strstr(getenv("QUERY_STRING"), cur_line_info->varname) != NULL)
            {
                update_bitmap(cur_line_info, bitmapLoc);
            }
        }
        if (funx_check_lineno != 0 && (strcmp(funx_check_filename, current_filename) != 0 || funx_check_lineno != current_lineno))
        {
            struct LineInfo *callee_info = get_info(current_filename, current_lineno, dist_info);
            struct LineInfo *info_to_be_added = get_info(funx_check_filename, funx_check_lineno, dist_info);
            if (callee_info != NULL && info_to_be_added == NULL)
            {
                insert_into_info_list(funx_check_filename, funx_check_lineno, callee_info->dist * 2, dist_info, taint_info);
            }
            funx_check_filename[0] = '\x00';
            funx_check_lineno = 0;
        }
        if (jmpx_check_lineno != 0 && strcmp(jmpx_check_filename, current_filename) == 0 && current_lineno != jmpx_check_lineno)
        {
            struct LineInfo *line_info_between = critical_between_last_and_cur_lineno(jmpx_check_filename, jmpx_check_lineno, current_lineno, dist_info);
            struct LineInfo *info_to_be_added = get_info(jmpx_check_filename, jmpx_check_lineno, dist_info);
            if (line_info_between != NULL && info_to_be_added == NULL)
            {
                insert_into_info_list(jmpx_check_filename, jmpx_check_lineno, line_info_between->dist * 2, dist_info, taint_info);
            }
            jmpx_check_filename[0] = '\x00';
            jmpx_check_lineno = 0;
        }
    }
    last_op = cur_op;
}
