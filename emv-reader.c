#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <PCSC/winscard.h>
#include "lists.h"

// APDU command structure, EMV_v4.3_Book_3 6.1
typedef struct {
  uint8_t class;
  uint8_t instruction;
  uint8_t param1;
  uint8_t param2;
  uint8_t data[512];
  uint8_t length_data;
  uint8_t length_expected;
} apdu_send_t;

// APDU response structure, EMV_v4.3_Book_3 6.2
typedef struct {
  uint16_t status_word;
  uint8_t data[512];
  uint8_t length;
} apdu_resp_t;

// TLV structure (Tag Length Value), EMV_v4.3_Book_3 Annex B
typedef struct {
  uint16_t tag;
  uint8_t length;
  uint8_t value[256];
} tlv_t;

// EMV application structure, EMV_v4.3_Book_1 12.2.3 table 47
typedef struct {
  tlv_t adf_name;
  tlv_t label;
  tlv_t preferred_name;
  tlv_t priority_indicator;
  tlv_t pdol; // Processing Options Data Object List, EMV_v4.3_Book_3 10.1
} emv_app_t;

// APDU instructions
const uint16_t EMV_SELECT       = 0x00A4; // EMV_v4.3_Book_1 11.3.2
const uint16_t EMV_GET_DATA     = 0x80CA; // EMV_v4.3_Book_3 6.5.7
const uint16_t EMV_READ_RECORD  = 0x00B2; // EMV_v4.3_Book_3 6.5.11
const uint16_t EMV_GET_PRC_OPT  = 0x80A8; // EMV_v4.3_Book_3 6.5.8
const uint16_t EMV_GET_RESPONSE = 0x00C0; // EMV_v4.3_Book_1 9.3.1.3

// Status words
const uint16_t EMV_SW_SUCCESS   = 0x9000;
const uint16_t EMV_SW_NOT_FOUND = 0x6A83;

const bool DEBUG = false;

// Check if tag is two bytes long, EMV_v4.3_Book_3 Annex B1
bool tag_is_two_bytes(uint8_t tag_first_byte) {
  return (tag_first_byte & 0x1F) == 0x1F;
}

// Check if TLV data length is two bytes long, EMV_v4.3_Book_3 Annex B2
bool length_is_two_bytes(uint8_t length_first_byte) {
  return length_first_byte == 0x81;
}

// Check if TLV is a constructed object, EMV_v4.3_Book_3 Annex B3
bool is_constructed_object(uint16_t tag) {
  return tag_is_two_bytes(tag >> 8) ? (0x2000 & tag) : (0x0020 & tag);
}

// Get a hex-string representation of a byte array
void get_hex(const uint8_t *data, int data_length, char *hex) {
  hex[0] = 0;
  char temp[4];
  for (int i=0; i<data_length; i++) {
    sprintf(temp, "%02x ", data[i]);
    strcat(hex, temp);
  }
}

uint8_t left_byte(uint16_t bytes) {
  return (bytes >> 8) & 0xFF;
}

uint8_t right_byte(uint16_t bytes) {
  return bytes & 0xFF;
}

// Extract TLV structure from byte array
void get_tlv(const uint8_t *data, size_t data_length, uint16_t tag, int occurrence, tlv_t *tlv) {
  int index = 0, matches = 0;
  uint16_t current_tag = 0;

  // Walk through data
  while (index < data_length) {
    // Get current tag and increment index
    if (tag_is_two_bytes(data[index])) {
      current_tag = (data[index] << 8) | data[index + 1];
      index += 2;
    } else {
      current_tag = data[index];
      index++;
    }

    // Check if match
    if (current_tag == tag) {
      if (++matches == occurrence) {
        tlv->tag = tag;
        tlv->length = length_is_two_bytes(data[index]) ? data[++index] : data[index];
        memcpy(tlv->value, &data[++index], tlv->length);
        return;
      }
    }

    // If primitive object then jump past it to next object
    index += is_constructed_object(current_tag) ? 1 : 1 + data[index];
  }

  tlv->tag = tag;
  tlv->length = 0;
}

// Send APDU to chip
bool apdu_exec(apdu_send_t *send, apdu_resp_t *resp) {
  // Get context
  SCARDCONTEXT card_context;
  LONG result = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &card_context);
  if (result != SCARD_S_SUCCESS) {
    fprintf(stderr, "%s: %s\n", "SCardEstablishContext", pcsc_stringify_error(result));
    return false;
  }

  // Get reader list
  LPTSTR readers;
  DWORD readers_length;
#ifdef SCARD_AUTOALLOCATE
  readers_length = SCARD_AUTOALLOCATE;
  result = SCardListReaders(card_context, NULL, (LPTSTR)&readers, &readers_length);
  if (result != SCARD_S_SUCCESS) {
    fprintf(stderr, "%s: %s\n", "SCardListReaders", pcsc_stringify_error(result));
    return false;
  }
#else
  result = SCardListReaders(card_context, NULL, NULL, &readers_length);
  if (result != SCARD_S_SUCCESS) {
    fprintf(stderr, "%s: %s\n", "SCardListReaders", pcsc_stringify_error(result));
    return false;
  }
  readers = calloc(readers_length, sizeof(char));
  result = SCardListReaders(card_context, NULL, readers, &readers_length);
  if (result != SCARD_S_SUCCESS) {
    fprintf(stderr, "%s: %s\n", "SCardListReaders", pcsc_stringify_error(result));
    return false;
  }
#endif

  // Connect
  SCARDHANDLE card;
  DWORD active_protocol;
  result = SCardConnect(card_context, readers, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &active_protocol);
  if (result != SCARD_S_SUCCESS) {
    fprintf(stderr, "%s: %s\n", "SCardConnect", pcsc_stringify_error(result));
    return false;
  }

  free(readers);

  // Get protocol
  SCARD_IO_REQUEST send_pci;
  switch (active_protocol) {
    case SCARD_PROTOCOL_T0:
      send_pci = *SCARD_PCI_T0;
      break;
    case SCARD_PROTOCOL_T1:
      send_pci = *SCARD_PCI_T1;
      break;
  }

  // Create command
  BYTE in[512];
  DWORD in_length = 0;
  in[in_length++] = send->class;
  in[in_length++] = send->instruction;
  in[in_length++] = send->param1;
  in[in_length++] = send->param2;
  if (send->length_data != 0) {
    in[in_length] = send->length_data;
    memcpy(&in[in_length + 1], send->data, send->length_data);
    in_length += send->length_data + 1;
  }
  in[in_length++] = send->length_expected;

  if (DEBUG) {
    char hex[1024];
    get_hex((unsigned char*)in, in_length, hex);
    printf("APDU send: %s\n", hex);
  }

  // Run command
  BYTE out[512];
  DWORD out_length = sizeof(out);
  result = SCardTransmit(card, &send_pci, in, in_length, NULL, out, &out_length);
  if (result != SCARD_S_SUCCESS) {
    fprintf(stderr, "%s: %s\n", "SCardTransmit", pcsc_stringify_error(result));
    return false;
  }

  if (DEBUG) {
    char hex[1024];
    get_hex((unsigned char*)&out, out_length, hex);
    printf("APDU resp: %s\n", hex);
  }

  // Adapt response
  if (out_length == 2) {
    resp->length = 0x00;
    resp->status_word = (out[0] << 8) | out[1];
  } else {
    memcpy(resp->data, out, out_length - 2);
    resp->length = out_length - 2;
    resp->status_word = (out[out_length - 2] << 8) |
        out[out_length - 1];
  }

  if (left_byte(resp->status_word) == 0x61) { // Response bytes still available
    apdu_send_t get;
    memset(&get, 0, sizeof(get));
    get.class = EMV_GET_RESPONSE >> 8;
    get.instruction = EMV_GET_RESPONSE & 0xFF;
    get.param1 = 0x00;
    get.param2 = 0x00;
    get.length_expected = right_byte(resp->status_word);
    return apdu_exec(&get, resp);
  } else if (left_byte(resp->status_word) == 0x6C) { // Wrong expected length
    send->length_expected = right_byte(resp->status_word);
    return apdu_exec(send, resp);
  } else {
    return true;
  }
}

void print_tlv_recursive(const tlv_t *current, int level) {
  printf("%*s%x-%s: (%d byte)\n", level * 2, "", current->tag,
      get_value(current->tag, LIST_TAGS), current->length);

  if (is_constructed_object(current->tag)) {
    int index = 0;
    while (index < current->length) {
      tlv_t next;

      if (tag_is_two_bytes(current->value[index])) {
        next.tag = (current->value[index] << 8) | current->value[index + 1];
        index += 2;
      } else {
        next.tag = current->value[index];
        index++;
      }

      next.length = length_is_two_bytes(current->value[index]) ?
          current->value[++index] : current->value[index];
      memcpy(next.value, &current->value[++index], next.length);

      print_tlv_recursive(&next, level + 1);
      index += next.length;
    }
  } else {
    char hex[1024];
    get_hex(current->value, current->length, hex);

    if (current->tag == 0x50 || current->tag == 0x5F20 || current->tag == 0x9F12) { // Special
      printf("%*s  s:\"%.*s\"\n", level * 2, "", current->length, current->value);
    } else {
      int wrap_width = 20;
      for (int i=0; i<current->length; i++) {
        if (i % wrap_width == 0)
          printf("%*s  ", level * 2, "");
        printf("%02x ", current->value[i]);
        if (i % wrap_width == wrap_width - 1 && i != current->length - 1)
          printf("\n");
      }
      printf("\n");
    }
  }
}

void print_tlv(const tlv_t *tlv) {
  if (!tlv->tag || !tlv->length)
    return;

  print_tlv_recursive(tlv, 0);

  printf("\n");
}

// Get EMV application using PSE (Payment System Enviroment), EMV_v4.3_Book_1 12.3.2
bool get_application(emv_app_t *application) {
  char PSE[] = "1PAY.SYS.DDF01";

  apdu_send_t apdu_send;
  apdu_send.class = EMV_SELECT >> 8;
  apdu_send.instruction = EMV_SELECT & 0xFF;
  apdu_send.param1 = 0x04;
  apdu_send.param2 = 0x00;
  apdu_send.length_data = strlen(PSE);
  apdu_send.length_expected = 0x00;
  memcpy(apdu_send.data, PSE, strlen(PSE));

  apdu_resp_t apdu_resp;
  if (!apdu_exec(&apdu_send, &apdu_resp))
    return false;

  if (apdu_resp.status_word != EMV_SW_SUCCESS) {
    fprintf(stderr, "Invalid status word: 0x%04x %s\n", apdu_resp.status_word,
        get_value(apdu_resp.status_word, LIST_STATUS_WORDS));
    return false;
  }

  // Get SFI (Short File Identifier)
  tlv_t sfi;
  memset(&sfi, 0, sizeof(sfi));
  get_tlv(apdu_resp.data, apdu_resp.length, 0x88, 1, &sfi);
  if (!sfi.length) {
    fprintf(stderr, "Short File Identifier (SFI) not found\n");
    return false;
  }

  // Walk through records
  int record = 0;
  while (record < 30) {
    memset(&apdu_send, 0, sizeof(apdu_send));
    apdu_send.class = EMV_READ_RECORD >> 8;
    apdu_send.instruction = EMV_READ_RECORD & 0xFF;
    apdu_send.param1 = (record + 1) & 0xFF;
    apdu_send.param2 = 0x04 | (sfi.value[0] << 3);
    apdu_send.length_expected = 0x00;

    if (!apdu_exec(&apdu_send, &apdu_resp))
      return false;

    if (apdu_resp.status_word == EMV_SW_NOT_FOUND)
      break;

    int entry = 1;
    while (1) {
      // Get directory, EMV_v4.3_Book_1 12.2.3 table 46
      tlv_t directory;
      memset(&directory, 0, sizeof(directory));
      get_tlv(apdu_resp.data, apdu_resp.length, 0x61, entry, &directory);
      if (!directory.length)
        break;

      // Get directory data, EMV_v4.3_Book_1 12.2.3 table 47
      tlv_t adf, label, pref, prio;
      memset(&adf, 0, sizeof(adf));
      memset(&label, 0, sizeof(label));
      memset(&pref, 0, sizeof(pref));
      memset(&prio, 0, sizeof(prio));
      get_tlv(apdu_resp.data, apdu_resp.length, 0x4F, entry, &adf);
      get_tlv(apdu_resp.data, apdu_resp.length, 0x50, entry, &label);
      get_tlv(apdu_resp.data, apdu_resp.length, 0x9F12, entry, &pref);
      get_tlv(apdu_resp.data, apdu_resp.length, 0x87, entry, &prio);

      // Check mandatory tags
      if (!adf.length || !label.length)
        break;

      entry++;

      // Set application
      memcpy(&application->adf_name, &adf, sizeof(tlv_t));
      memcpy(&application->label, &label, sizeof(tlv_t));
      if (pref.length)
        memcpy(&application->preferred_name, &pref, sizeof(tlv_t));
      if (prio.length)
        memcpy(&application->priority_indicator, &prio, sizeof(tlv_t));

      return true;
    }

    record++;
  }

  fprintf(stderr, "No application found\n");
  return false;
}

// Select application and extract PDOL, EMV_v4.3_Book_1 12, EMV_v4.3_Book_3 10.1
bool select_application(emv_app_t *application) {
  apdu_send_t apdu_send;
  apdu_send.class = EMV_SELECT >> 8;
  apdu_send.instruction = EMV_SELECT & 0xFF;
  apdu_send.param1 = 0x04;
  apdu_send.param2 = 0x00;
  apdu_send.length_data = application->adf_name.length;
  apdu_send.length_expected = 0x00;
  memcpy(apdu_send.data, application->adf_name.value, application->adf_name.length);

  apdu_resp_t apdu_resp;
  if (!apdu_exec(&apdu_send, &apdu_resp))
    return false;

  if (apdu_resp.status_word != EMV_SW_SUCCESS) {
    fprintf(stderr, "Invalid status word: 0x%04x %s\n", apdu_resp.status_word,
        get_value(apdu_resp.status_word, LIST_STATUS_WORDS));
    return false;
  }

  tlv_t df;
  memset(&df, 0, sizeof(df));
  get_tlv(apdu_resp.data, apdu_resp.length, 0x84, 1, &df);

  // If DF has same length and data as app ADF, then select is successful
  if (df.length != application->adf_name.length ||
      memcmp(&df.value, application->adf_name.value, df.length)) {
    fprintf(stderr, "Application selection failed\n");
    return false;
  }

  get_tlv(apdu_resp.data, apdu_resp.length, 0x9F38, 1, &application->pdol);

  return true;
}

bool get_records(emv_app_t *application, tlv_t **records, size_t *records_length) {
  apdu_send_t apdu_send;
  memset(&apdu_send, 0, sizeof(apdu_send));
  apdu_send.class = EMV_GET_PRC_OPT >> 8;
  apdu_send.instruction = EMV_GET_PRC_OPT & 0xFF;
  apdu_send.param1 = 0x00;
  apdu_send.param2 = 0x00;
  apdu_send.length_expected = 0x00;

  // Handle PDOL
  if (!application->pdol.length) {
    apdu_send.length_data = 2;
    apdu_send.data[0] = 0x83;
    apdu_send.data[1] = 0x00;
  } else {
    uint8_t data[256];
    uint8_t data_length = 0;
    uint8_t pdol_i = 0;

    while (pdol_i < application->pdol.length) {
      pdol_i += tag_is_two_bytes(application->pdol.value[pdol_i]) ? 2 : 1;
      memset(&data[data_length], 0, application->pdol.value[pdol_i]);
      data_length += application->pdol.value[pdol_i];
      pdol_i++;
    }

    // Assign to APDU message
    apdu_send.length_data = data_length + 2;
    apdu_send.data[0] = 0x83;
    apdu_send.data[1] = data_length;
    memcpy(&apdu_send.data[2], data, data_length);
  }

  apdu_resp_t apdu_resp;
  if (!apdu_exec(&apdu_send, &apdu_resp))
    return false;

  if (apdu_resp.status_word != EMV_SW_SUCCESS) {
    fprintf(stderr, "Invalid status word: 0x%04x %s\n", apdu_resp.status_word,
        get_value(apdu_resp.status_word, LIST_STATUS_WORDS));
    return false;
  }

  // Extract AIP and AFL, EMV_v4.3_Book_3 6.5.8.4
  tlv_t aip, afl;
  memset(&aip, 0, sizeof(aip));
  memset(&afl, 0, sizeof(afl));
  if (apdu_resp.data[0] == 0x77) { // Format 2
    get_tlv(apdu_resp.data, apdu_resp.length, 0x82, 1, &aip);
    get_tlv(apdu_resp.data, apdu_resp.length, 0x94, 1, &afl);
  } else if (apdu_resp.data[0] == 0x80) { // Format 1
    aip.tag = 0x82;
    aip.length = 2;
    aip.value[0] = apdu_resp.data[2];
    aip.value[1] = apdu_resp.data[3];

    afl.tag = 0x94;
    afl.length = apdu_resp.data[1] - 2;
    memcpy(afl.value, &apdu_resp.data[4], afl.length);
  }

  // Save AIP and AFL to list
  *records = realloc(*records, 2 * sizeof(tlv_t));
  if (*records == NULL) {
    fprintf(stderr, "Out of memory\n");
    return false;
  }
  memcpy(*records, &aip, sizeof(tlv_t));
  memcpy(*records + 1, &afl, sizeof(tlv_t));
  *records_length = 2;

  // AIP and AFL extracted, begin reading records, EMV_v4.3_Book_3 10.2
  uint8_t afl_index = 0;
  while (afl_index < afl.length) {
    uint8_t sfi = afl.value[afl_index];
    uint8_t current = afl.value[afl_index + 1];
    uint8_t last = afl.value[afl_index + 2];

    while (current <= last) {
      memset(&apdu_send, 0, sizeof(apdu_send));
      memset(&apdu_resp, 0, sizeof(apdu_resp));

      apdu_send.class = EMV_READ_RECORD >> 8;
      apdu_send.instruction = EMV_READ_RECORD & 0xFF;
      apdu_send.param1 = current;
      apdu_send.param2 = 0x04 | sfi;
      apdu_send.length_expected = 0x00;

      if (!apdu_exec(&apdu_send, &apdu_resp))
        return false;

      if (apdu_resp.status_word != EMV_SW_SUCCESS) {
        fprintf(stderr, "Invalid status word: 0x%04x %s\n", apdu_resp.status_word,
            get_value(apdu_resp.status_word, LIST_STATUS_WORDS));
        return false;
      }

      tlv_t data;
      memset(&data, 0, sizeof(tlv_t));
      get_tlv(apdu_resp.data, apdu_resp.length, 0x70, 1, &data);

      // Save TLV to list
      *records = realloc(*records, ((*records_length) + 1) * sizeof(tlv_t));
      if (*records == NULL) {
        fprintf(stderr, "Out of memory\n");
        return false;
      }
      memcpy(*records + (*records_length)++, &data, sizeof(tlv_t));

      current++;
    }

    afl_index += 4;
  }

  // Also get Application Transaction Counter (ATC), PIN Try Counter,
  // Last Online ATC Register and Log Format, EMV_v4.3_Book_3 7.3
  uint16_t more_tags[] = { 0x9F36, 0x9F17, 0x9F13, 0x9F4f };

  for (int i=0; i<4; i++) {
    memset(&apdu_send, 0, sizeof(apdu_send));
    apdu_send.class = EMV_GET_DATA >> 8;
    apdu_send.instruction = EMV_GET_DATA & 0xFF;
    apdu_send.param1 = left_byte(more_tags[i]);
    apdu_send.param2 = right_byte(more_tags[i]);

    memset(&apdu_resp, 0, sizeof(apdu_resp));
    if (apdu_exec(&apdu_send, &apdu_resp) && apdu_resp.status_word == EMV_SW_SUCCESS) {
      tlv_t data;
      memset(&data, 0, sizeof(data));
      get_tlv(apdu_resp.data, apdu_resp.length, more_tags[i], 1, &data);

      *records = realloc(*records, ((*records_length) + 1) * sizeof(tlv_t));
      if (*records == NULL) {
        fprintf(stderr, "Out of memory\n");
        return false;
      }
      memcpy(*records + (*records_length)++, &data, sizeof(tlv_t));
    }
  }

  return true;
}

int main(int argc, char **argv) {
  emv_app_t application;
  memset(&application, 0, sizeof(application));

  if (get_application(&application) && select_application(&application)) {
    print_tlv(&application.adf_name);
    print_tlv(&application.label);
    print_tlv(&application.preferred_name);
    print_tlv(&application.priority_indicator);
    print_tlv(&application.pdol);

    size_t records_length = 0;
    tlv_t *records = NULL;

    get_records(&application, &records, &records_length);

    if (records != NULL) {
      for (size_t i=0; i<records_length; i++)
        print_tlv(&records[i]);

      free(records);
    }
  }

  return 0;
}