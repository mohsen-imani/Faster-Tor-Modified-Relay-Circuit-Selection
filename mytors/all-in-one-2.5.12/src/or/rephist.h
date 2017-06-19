/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rephist.h
 * \brief Header file for rephist.c.
 **/
#include "routerlist.h"
#ifndef TOR_REPHIST_H
#define TOR_REPHIST_H

void rep_hist_init(void);
void rep_hist_note_connect_failed(const char* nickname, time_t when);
void rep_hist_note_connect_succeeded(const char* nickname, time_t when);
void rep_hist_note_disconnect(const char* nickname, time_t when);
void rep_hist_note_connection_died(const char* nickname, time_t when);
void rep_hist_note_extend_succeeded(const char *from_name,
                                    const char *to_name);
void rep_hist_note_extend_failed(const char *from_name, const char *to_name);
void rep_hist_dump_stats(time_t now, int severity);
void rep_hist_note_bytes_read(size_t num_bytes, time_t when);
void rep_hist_note_bytes_written(size_t num_bytes, time_t when);

void rep_hist_make_router_pessimal(const char *id, time_t when);

void rep_hist_note_dir_bytes_read(size_t num_bytes, time_t when);
void rep_hist_note_dir_bytes_written(size_t num_bytes, time_t when);

int rep_hist_bandwidth_assess(void);
char *rep_hist_get_bandwidth_lines(void);
void rep_hist_update_state(or_state_t *state);
int rep_hist_load_state(or_state_t *state, char **err);
void rep_history_clean(time_t before);

void rep_hist_note_router_reachable(const char *id, const tor_addr_t *at_addr,
                                    const uint16_t at_port, time_t when);
void rep_hist_note_router_unreachable(const char *id, time_t when);
int rep_hist_record_mtbf_data(time_t now, int missing_means_down);
int rep_hist_load_mtbf_data(time_t now);

time_t rep_hist_downrate_old_runs(time_t now);
long rep_hist_get_uptime(const char *id, time_t when);
double rep_hist_get_stability(const char *id, time_t when);
double rep_hist_get_weighted_fractional_uptime(const char *id, time_t when);
long rep_hist_get_weighted_time_known(const char *id, time_t when);
int rep_hist_have_measured_enough_stability(void);

void rep_hist_note_used_port(time_t now, uint16_t port);
smartlist_t *rep_hist_get_predicted_ports(time_t now);
void rep_hist_remove_predicted_ports(const smartlist_t *rmv_ports);
void rep_hist_note_used_resolve(time_t now);
void rep_hist_note_used_internal(time_t now, int need_uptime,
                                 int need_capacity);
int rep_hist_get_predicted_internal(time_t now, int *need_uptime,
                                    int *need_capacity);

int any_predicted_circuits(time_t now);
int rep_hist_circbuilding_dormant(time_t now);

void note_crypto_pk_op(pk_op_t operation);
void dump_pk_ops(int severity);

void rep_hist_exit_stats_init(time_t now);
void rep_hist_reset_exit_stats(time_t now);
void rep_hist_exit_stats_term(void);
char *rep_hist_format_exit_stats(time_t now);
time_t rep_hist_exit_stats_write(time_t now);
void rep_hist_note_exit_bytes(uint16_t port, size_t num_written,
                              size_t num_read);
void rep_hist_note_exit_stream_opened(uint16_t port);

void rep_hist_buffer_stats_init(time_t now);
void rep_hist_buffer_stats_add_circ(circuit_t *circ,
                                    time_t end_of_interval);
time_t rep_hist_buffer_stats_write(time_t now);
void rep_hist_buffer_stats_term(void);
void rep_hist_add_buffer_stats(double mean_num_cells_in_queue,
     double mean_time_cells_in_queue, uint32_t processed_cells);
char *rep_hist_format_buffer_stats(time_t now);
void rep_hist_reset_buffer_stats(time_t now);

void rep_hist_desc_stats_init(time_t now);
void rep_hist_note_desc_served(const char * desc);
void rep_hist_desc_stats_term(void);
time_t rep_hist_desc_stats_write(time_t now);

void rep_hist_conn_stats_init(time_t now);
void rep_hist_note_or_conn_bytes(uint64_t conn_id, size_t num_read,
                                 size_t num_written, time_t when);
void rep_hist_reset_conn_stats(time_t now);
char *rep_hist_format_conn_stats(time_t now);
time_t rep_hist_conn_stats_write(time_t now);
void rep_hist_conn_stats_term(void);

void rep_hist_note_circuit_handshake_requested(uint16_t type);
void rep_hist_note_circuit_handshake_assigned(uint16_t type);
void rep_hist_log_circuit_handshake_stats(time_t now);

void rep_hist_free_all(void);
//iSec:--------------------------------------
typedef struct predicted_destination{
  float lat;
  float lon;
  int num;
  float sum_lat;
  float sum_lon;
  int total;
} predicted_destination;


typedef struct time_sendmes{
   int flag_sent;
   int flag_received;
   struct timeval t;
} time_sendmes; 

typedef struct my_bucket {
   circid_t ID;
   long rtt;
   float distance;
} my_bucket; 


typedef struct weight_idx {
   int idx;
   double weight;
} weight_idx; 


typedef union u64_dbl_t {
  uint64_t u64;
  double dbl;
} u64_dbl_t;


float close_dest_lat;
float close_dest_lon;
extern int SPARAM;

void add_to_list(circuit_t *circ, long rtt);
smartlist_t *rep_hist_get_predicted_destination(void);//
void predicted_destination_init(void);//
void add_predicted_destination(float lat, float lon, int num);//
double  compute_distance(float lat1, float lon1, float lat2, float lon2);
double compute_weight_moh(double bw, double max_bw, double dis, double max_dis,bandwidth_weight_rule_t rule);
double gimme_new_weight(double w);
int compare_d (const void *v1, const void *v2);
void print_list(circuit_t *circ);
long get_mean_list(circuit_t *circ, int a);
int get_length_of_list(circuit_t *circ);
int is_list_empty(circuit_t *circ);
int selected_index(const u64_dbl_t *entries, int n);
int rand_sl(int n);
int compare (const void *v1, const void *v2);
int* get_rand(int c);
circuit_t * circuit_get_by_id(circid_t id);
int update_s_param(int L);
int get_bucket_size(int option, int len);
double change_distance_weights(double wd,bandwidth_weight_rule_t rule);
//isec-----------------------------------------------
#endif

