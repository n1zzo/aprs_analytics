#include <arpa/inet.h>
#include <errno.h>
#include <fap.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>
#include <libpq-fe.h>
#include <threads.h>
#include <time.h>
#include "toml.h"

#define AUTH_STR_LEN 256
#define ERR_STR_LEN 256
#define CONNINFO_LEN 256

static void error(const char* msg, const char* msg1)
{
  fprintf(stderr, "Error: %s%s\n", msg, msg1?msg1:"");
  exit(1);
}

// Datatype of the nodes of the linked list of packets
typedef struct pkt_node_t {
  time_t timestamp;
  fap_packet_t *packet;
  struct pkt_node_t *next;
} pkt_node_t;

// Threads data structures
typedef struct thr_data_t {
  int sockfd; // aprsc socket
  pkt_node_t *pkt_list; // packets list
  mtx_t list_mutex; // packets list muted
  bool duplicates; // this thread parses duplicates
} thr_data_t;
                
// Enqueue new node at the end of the list
void list_enqueue(pkt_node_t **head, fap_packet_t *packet) {
  // Populate new node
  pkt_node_t *node = (pkt_node_t *) malloc(sizeof(pkt_node_t));
  node->timestamp = time(NULL);
  node->packet = packet;
  node->next = NULL;
  // Empty list
  if (*head == NULL) {
    *head = node;
    return;
  }
  // Traverse the list until the end
  pkt_node_t *cur = NULL;
  for(cur = *head; cur->next != NULL; cur = cur->next);
  cur->next = node;
}

// Remove a packet from the head of the list
fap_packet_t *list_dequeue(pkt_node_t **head) {
  // Empty list
  if (*head == NULL)
    return 0;
  fap_packet_t *packet = (*head)->packet;
  pkt_node_t *old_head = *head;
  *head = (*head)->next;
  free(old_head);
  return packet;
}

// Older than x seconds
bool is_older(time_t ts, int x) {
  return difftime(time(NULL), ts) > (double) x;
}

// Sweep the list and remove packets older than 30s, assume ordered list
void list_cleanup(pkt_node_t **head) {
  // Empty list
  if (*head == NULL)
    return;
  // Delete until the current node is younger than 30s
  for(pkt_node_t *cur = *head; cur->next != NULL && is_older(cur->timestamp, 30); cur = *head) {
    pkt_node_t *old_head = cur;
    *head = cur->next;
    fap_free(old_head->packet);
    free(old_head);
  }
}

size_t list_size(pkt_node_t *head) {
  // Empty list
  if (head == NULL)
    return 0;
  size_t list_size = 0;
  // Delete until the current node is younger than 30s
  for(pkt_node_t *cur = head; cur->next != NULL; cur = cur->next)
    list_size++;
  return list_size;
}

toml_table_t *parse_settings() {
  FILE* fp;
  char errbuf[200];

  // 1. Read and parse toml file
  fp = fopen("config.toml", "r");
  if (!fp) {
      error("cannot open config.toml - ", strerror(errno));
  }

  toml_table_t* conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
  fclose(fp);

  if (!conf) {
      error("cannot parse - ", errbuf);
  }

  return conf;
}

// Open a TCP socket
int open_socket(char *host, int port) {
  // Get protocol
  struct protoent *protoent = getprotobyname("tcp");
  if (protoent == NULL) {
    perror("Error in getprotobyname");
    return -1;
  }
  // Open socket
  int sockfd = socket(AF_INET, SOCK_STREAM, protoent->p_proto);
  if (sockfd == -1) {
    perror("Error opening socket");
    return -1;
  }
  // Get hostname
  struct hostent *hostent = gethostbyname(host);
  if (hostent == NULL) {
    fprintf(stderr, "Error: gethostbyname(\"%s\")\n", host);
    return -1;
  }
  in_addr_t in_addr = inet_addr(inet_ntoa(*(struct in_addr*)*(hostent->h_addr_list)));
  if (in_addr == (in_addr_t)-1) {
    fprintf(stderr, "Error: inet_addr(\"%s\")\n", *(hostent->h_addr_list));
    return -1;
  }
  struct sockaddr_in sockaddr_in;
  sockaddr_in.sin_addr.s_addr = in_addr;
  sockaddr_in.sin_family = AF_INET;
  sockaddr_in.sin_port = htons(port);
  // Open connection
  if (connect(sockfd, (struct sockaddr*)&sockaddr_in, sizeof(sockaddr_in)) == -1) {
    perror("connect");
    return -1;
  }

  return sockfd;
}

int open_aprsc_conn(toml_table_t *conf, bool duplicates) {
  char buffer[BUFSIZ];

  toml_table_t* aprsc_conf = toml_table_in(conf, "aprsc");
  if (!aprsc_conf) {
      error("missing [aprsc]", "");
  }
  toml_datum_t aprsc_host = toml_string_in(aprsc_conf, "host");
  if (!aprsc_host.ok) {
      error("cannot read aprsc.host", "");
  }
  toml_datum_t aprsc_port;
  if (!duplicates)
     aprsc_port = toml_int_in(aprsc_conf, "port");
  else
     aprsc_port = toml_int_in(aprsc_conf, "dup_port");
  if (!aprsc_port.ok) {
      error("cannot read aprsc.port", "");
  }
  toml_datum_t aprsc_user;
  if (!duplicates)
    aprsc_user = toml_string_in(aprsc_conf, "user");
  else
    aprsc_user = toml_string_in(aprsc_conf, "dup_user");
  if (!aprsc_user.ok) {
      error("cannot read aprsc.user", "");
  }
  toml_datum_t aprsc_password;
  if (!duplicates)
    aprsc_password = toml_string_in(aprsc_conf, "password");
  else
    aprsc_password = toml_string_in(aprsc_conf, "dup_password");
  if (!aprsc_host.ok) {
      error("cannot read aprsc.password", "");
  }

  // Open socket
  int sockfd = open_socket(aprsc_host.u.s, aprsc_port.u.i);

  // Authenticate to aprsc
  char auth_str[AUTH_STR_LEN] = { 0 };
  snprintf(auth_str,
           AUTH_STR_LEN,
           "user %s pass %s vers aprs_analytics0.1\n",
           aprsc_user.u.s,
           aprsc_password.u.s);
  size_t auth_str_len = strnlen(auth_str, AUTH_STR_LEN);
  write(sockfd, auth_str, auth_str_len);
  // Receive aprsc version
  int n_read = read(sockfd, buffer, BUFSIZ);
  printf("%.*s", n_read, buffer);
  // Receive login response
  n_read = read(sockfd, buffer, BUFSIZ);
  printf("%.*s", n_read, buffer);

  free(aprsc_host.u.s);
  free(aprsc_user.u.s);
  free(aprsc_password.u.s);

  return sockfd;
}

// Nicely close a PosgreSQL DB connection
static void exit_nicely(PGconn *conn)
{
    PQfinish(conn);
    exit(1);
}

// Open a connection to a PosgreSQL DB
PGconn *open_db_conn(toml_table_t *conf) {
  char conninfo[CONNINFO_LEN] = { 0 };
  PGconn     *conn;
  PGresult   *res;
  int         nFields;
  int         i,
              j;

  toml_table_t* db_conf = toml_table_in(conf, "db");
  if (!db_conf) {
      error("missing [db]", "");
  }
  toml_datum_t db_host = toml_string_in(db_conf, "host");
  if (!db_host.ok) {
      error("cannot read db.host", "");
  }
  toml_datum_t db_port = toml_int_in(db_conf, "port");
  if (!db_port.ok) {
      error("cannot read db.port", "");
  }
  toml_datum_t db_database = toml_string_in(db_conf, "database");
  if (!db_database.ok) {
      error("cannot read db.database", "");
  }
  toml_datum_t db_user = toml_string_in(db_conf, "user");
  if (!db_user.ok) {
      error("cannot read db.user", "");
  }
  toml_datum_t db_password = toml_string_in(db_conf, "password");
  if (!db_password.ok) {
      error("cannot read db.password", "");
  }

  // This string defines the database to be opened
  snprintf(conninfo,
           CONNINFO_LEN,
           "host=%s port=%d dbname=%s user=%s password=%s",
           db_host.u.s,
           db_port.u.i,
           db_database.u.s,
           db_user.u.s,
           db_password.u.s);

  /* Make a connection to the database */
  conn = PQconnectdb(conninfo);

  /* Check to see that the backend connection was successfully made */
  if (PQstatus(conn) != CONNECTION_OK)
  {
    fprintf(stderr, "%s", PQerrorMessage(conn));
    exit_nicely(conn);
  }

  free(db_host.u.s);
  free(db_database.u.s);
  free(db_user.u.s);
  free(db_password.u.s);

  return conn;
}
/*
const char insert_station_cmd[] = "INSERT INTO stations (callsign) "
                                  "SELECT ($1::varchar) "
                                  "WHERE NOT EXISTS (SELECT 1 "
                                                    "FROM stations "
                                                    "WHERE callsign = $1::varchar);";
const char insert_station_cmd[] = "WITH input_data(callsing_in, latitude_in, longitude_in) AS ("
          " SELECT $1::varchar, $2::real, $3::real"
          "), "
          "station_insert AS ("
                                  " INSERT INTO stations (callsign, symbol) "
                                  " VALUES ($1::varchar, $5::smallint)"
                                  " ON CONFLICT DO NOTHING"
          " returning stationid"
          "), "
          "position_insert AS ("
          " INSERT INTO positions (ts_start, point, ts_stop, station_id)"
                                  " SELECT NOW(), ST_MakePoint(s1.longitude_in, s1.latitude_in), NOW(), s2.stationid "
                                  " FROM input_data s1, station_insert s2"
          " returning gid"
          ") "
          "INSERT INTO payloads (station_id, message, ts_message, position_id)"
                                  " SELECT s2.stationid, $4::varchar, NOW(), s3.gid "
                                  " FROM input_data s1, station_insert s2, position_insert s3;";
*/
const char insert_station_cmd[] = "CALL sp_insert_station("
                                  "    callsign_in => $1::character varying,"
                                  "    latitude_in => $2::real,"
                                  "   longitude_in => $3::real,"
                                  "     message_in => $4::character varying,"
                                  "      symbol_in => $5::smallint"
                                  ");";

// Log an APRS packet into the DB
void log_packet(fap_packet_t *packet, PGconn *conn) {
  // Log any station that sends a location packet
  if ( packet->src_callsign && packet->latitude && packet->longitude)
  {
/*
    printf("\nGot geo packet from %s <%lf,%lf>.\nSymb tbl %d code %d -> %d\n",
           packet->src_callsign,
           *(packet->latitude),
           *(packet->longitude),
           packet->symbol_table,
           packet->symbol_code,
           packet->symbol_table*256 + packet->symbol_code - 32768);
*/
    char packet_latitude[10];
    snprintf(packet_latitude, 10, "%.5lf\n", *(packet->latitude));
    char packet_longitude[10];
    snprintf(packet_longitude, 10, "%.5lf\n", *(packet->longitude));
    char packet_symbol[10];
    snprintf(packet_symbol, 10, "%d\n", packet->symbol_table*256 + packet->symbol_code - 32768);

    // printf("packet_symbol = %s", packet_symbol);

    const char *paramValues[5] = { packet->src_callsign, packet_latitude, packet_longitude, packet->comment, packet_symbol };

    int resultFormat = 0;

    PGresult *res = PQexecParams(conn, insert_station_cmd, 5, NULL, paramValues, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      printf("PQexecParames failed: %s\n", PQresultErrorMessage(res));
    }
    // Should PQclear PGresult whenever it is no longer needed to avoid memory leaks
    PQclear(res);
  }
}

// Parse APRS packet using libfap, and enqueue into a queue
fap_packet_t *parse_enqueue_packet(char *buf, int len, thr_data_t *thr_data) {
  fap_packet_t* packet = fap_parseaprs(buf, len, 0);
  if ( packet->error_code )
  {
    char err_str[ERR_STR_LEN] = { 0 };
    fap_explain_error(*packet->error_code, err_str);
    printf("Failed to parse packet (%.*s): %s\n", (int)(len - 1), buf, err_str);
  }
  else
  {
    mtx_lock(&(thr_data->list_mutex));
    list_enqueue(&(thr_data->pkt_list), packet);
    mtx_unlock(&(thr_data->list_mutex));
  }
  return packet;
}

void *packets_thread(void *thr_data_ptr) {
  char buffer[BUFSIZ];
  int n_read = 0;
  int tot_read = 0;
  thr_data_t *thr_data = (thr_data_t *) thr_data_ptr;
  PGconn *conn;

  // Connect to APRSC server
  toml_table_t *conf = parse_settings();
  toml_table_t* aprsc_conf = toml_table_in(conf, "aprsc");
  if (!aprsc_conf) {
      error("missing [aprsc]", "");
  }

  // Thread 0 needs connection to DB
  if (!thr_data->duplicates)
    conn = open_db_conn(conf);

  while (1) {
    // Receive a chunk of data
    n_read = read(thr_data->sockfd, buffer + tot_read, BUFSIZ - tot_read);
    tot_read += n_read;

    // For each line, process an APRS packet
    for(int i = 0; i < tot_read; i++) {
      if (buffer[i] == '\r' || buffer[i] == '\n') {
        buffer[i] = '\0';
        if (!thr_data->duplicates)
          printf("\nRCVD: %s", buffer);
        else
          printf("\nDUP: %s", buffer);
        if (buffer[0] == '#')
        {
          tot_read = 0;
          continue;
        }
        // If not duplicate enqueue and upload
        if (!thr_data->duplicates) {
          fap_packet_t *packet = parse_enqueue_packet(buffer, i+1, thr_data);
          log_packet(packet, conn);
        // Otherwise just enqueue
        } else {
          // Strip leading dup and whitespaces
          int j = 3;
          for(; j < tot_read && (buffer[j] < 'A' || buffer[j] > 'Z'); j++);
          parse_enqueue_packet(buffer + j, i+1, thr_data);
        }
        tot_read = 0;
      }
    }
  }
  close(thr_data->sockfd);

  // Close FAP
  fap_cleanup();

  // Free toml config memory
  toml_free(conf);

  thrd_exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
  bool print_stats = true;
  thrd_t packets_thrd, duplicates_thread;

  // Initialize APRS Parser
  fap_init();

  // Parse config file
  toml_table_t *conf = parse_settings();

  // Open connection to DB
  PGconn *conn = open_db_conn(conf);

  // Initialize threads data structures, thr 0: packets, thr 1: duplicates
  thr_data_t thr_data[2] = { 0 };
  thr_data[0].sockfd = open_aprsc_conn(conf, false);
  int ret = mtx_init(&(thr_data[0].list_mutex), mtx_plain);
  thr_data[1].sockfd = open_aprsc_conn(conf, true);
  ret = mtx_init(&(thr_data[1].list_mutex), mtx_plain);
  thr_data[1].duplicates = true;

  // Start thread to fetch APRS packets
  for(long i = 0; i < 2; i++) {
    ret = thrd_create(&packets_thrd, (thrd_start_t)packets_thread, (void *)&(thr_data[i]));
    if (ret == thrd_error) {
      printf("ERORR; thrd_create() call failed for thread %d\n", i);
      exit(EXIT_FAILURE);
    }
  }

  // Main loop for matching packets and duplicates and logging to the db
  while (1) {
    // Fetch from duplicates queue
    mtx_lock(&(thr_data[1].list_mutex));
    fap_packet_t *packet = list_dequeue(&(thr_data[1].pkt_list));
    mtx_unlock(&(thr_data[1].list_mutex));
    // If list is empty packet is equal to 0, if no packet in main list, skip
    if (packet != 0 && thr_data[0].pkt_list != NULL) {
      // Try to match main packets queue
      mtx_lock(&(thr_data[0].list_mutex));
      for(pkt_node_t *cur = thr_data[0].pkt_list; cur->next != NULL; cur = cur->next) {
        // If source callsign and comment match
        if(!strcmp(packet->src_callsign, cur->packet->src_callsign)) {
          // printf("Matching:\n[%s]==[%s]\n[%s]==[%s]\n",
          //        packet->src_callsign,
          //        cur->packet->src_callsign,
          //        packet->comment,
          //        cur->packet->comment);
          if (packet->comment && cur->packet->comment &&
              !strcmp(packet->comment, cur->packet->comment)) {
            printf("\nGot a match for duplicate:\n%s> %s\n",
                   packet->src_callsign,
                   packet->comment);
            // TODO: Upload duplicate packet to DB
            break;
          }
        }
      }
      mtx_unlock(&(thr_data[0].list_mutex));
    }
    // Sweep main list to remove packets older than 30s
    mtx_lock(&(thr_data[0].list_mutex));
    list_cleanup(&(thr_data[0].pkt_list));
    mtx_unlock(&(thr_data[0].list_mutex));
    // Statistics
    if (!(time(NULL) % 10)) {
      if (print_stats) {
        printf("\nThe main list contains %d packets\n", list_size(thr_data[0].pkt_list));
        printf("The duplicates list contains %d packets\n", list_size(thr_data[1].pkt_list));
      }
      print_stats = false;
    } else
      print_stats = true;
  }

  // Close DB
  exit_nicely(conn);

  thrd_exit(EXIT_SUCCESS);
}
