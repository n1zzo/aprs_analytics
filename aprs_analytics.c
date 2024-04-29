#include <arpa/inet.h>
#include <errno.h>
#include <fap.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

int open_aprsc_conn(toml_table_t *conf) {
  char buffer[BUFSIZ];

  toml_table_t* aprsc_conf = toml_table_in(conf, "aprsc");
  if (!aprsc_conf) {
      error("missing [aprsc]", "");
  }
  toml_datum_t aprsc_host = toml_string_in(aprsc_conf, "host");
  if (!aprsc_host.ok) {
      error("cannot read aprsc.host", "");
  }
  toml_datum_t aprsc_port = toml_int_in(aprsc_conf, "port");
  if (!aprsc_port.ok) {
      error("cannot read aprsc.port", "");
  }
  toml_datum_t aprsc_user = toml_string_in(aprsc_conf, "user");
  if (!aprsc_user.ok) {
      error("cannot read aprsc.user", "");
  }
  toml_datum_t aprsc_password = toml_string_in(aprsc_conf, "password");
  if (!aprsc_host.ok) {
      error("cannot read aprsc.password", "");
  }

  // Open socket to APRSC
  int sockfd = open_socket(aprsc_host.u.s, aprsc_port.u.i);

  // Authenticate to aprsc
  char auth_str[AUTH_STR_LEN] = { 0 };
  snprintf(auth_str, AUTH_STR_LEN, "user %s pass %s vers aprs_analytics0.1\n", aprsc_user.u.s, aprsc_password.u.s);
  size_t auth_str_len = strnlen(auth_str, AUTH_STR_LEN);
  write(sockfd, auth_str, auth_str_len);
  // Receive aprsc version
  read(sockfd, buffer, BUFSIZ);
  puts(buffer);
  // Receive login response
  read(sockfd, buffer, BUFSIZ);
  puts(buffer);

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
  snprintf(conninfo, CONNINFO_LEN, "host=%s port=%d dbname=%s user=%s password=%s", db_host.u.s, db_port.u.i, db_database.u.s, db_user.u.s, db_password.u.s);

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
*/
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

    printf("packet_symbol = %s", packet_symbol);

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

// Parse APRS packet using libfap
void parse_packet(char *buf, int len, PGconn *conn) {
  fap_packet_t* packet = fap_parseaprs(buf, len, 0);
  if ( packet->error_code )
  {
    char err_str[ERR_STR_LEN] = { 0 };
    fap_explain_error(*packet->error_code, err_str);
    printf("Failed to parse packet (%.*s): %s\n", (int)(len - 1), buf, err_str);
  }
  else
  {
    log_packet(packet, conn);
  }
  fap_free(packet);
}

int main(int argc, char *argv[])
{
  char buffer[BUFSIZ];
  int n_read = 0;
  int tot_read = 0;

  toml_table_t *conf = parse_settings();

  // Initialize APRS Parser
  fap_init();

  // Open connection to DB
  PGconn *conn = open_db_conn(conf);

  // Connect to APRSC server
  int sockfd = open_aprsc_conn(conf);

  // Main loop for getting and parsing APRS packets
  while (1) {
    // Receive a chunk of data
    n_read = read(sockfd, buffer + tot_read, BUFSIZ - tot_read);
    tot_read += n_read;

    // For each line, process an APRS packet
    for(int i = 0; i < tot_read; i++) {
      if (buffer[i] == '\r' || buffer[i] == '\n') {
        buffer[i] = '\0';
        printf("\nRCVD: %s", buffer);
        if (buffer[0] == '#')
        {
          tot_read = 0;
          continue;
        }
        parse_packet(buffer, i+1, conn);
        tot_read = 0;
      }
    }
  }

  // Close FAP
  fap_cleanup();

  // Close socket
  close(sockfd);

  // Close DB
  exit_nicely(conn);

  // Free toml config memory
  toml_free(conf);

  return 0;
}
