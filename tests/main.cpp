#include <iostream>

// Declare tests:
void test_rns_and_ntt_roundtrip();
void test_paramgen();
void test_modulus_chain();

void test_poly_add_sub_scalar();
void test_ntt_roundtrip_all_moduli();
void test_ntt_convolution();
void test_ckks_params();
void test_plaintext_ciphertext_basic();
void test_encoder_basic_small_N();
void test_encoder_random_full_slots();
void test_encoder_multiple_levels();
void test_encoder_edge_values();

void test_secret_key_ternary();
void test_secret_key_deterministic();
void test_public_key_relation();
void test_public_key_structure();

void test_small_vector();
void test_random_vector();
void test_multi_scale();
void test_multiple_rounds();

void  test_eval_add();
void  test_eval_sub();
void  test_eval_neg();
void  test_eval_add_plain();

void  test_multiply_raw();
void  test_multiply_relinearize();

void  test_rescale_metadata();
void  test_rescale_after_mul();

void  test_conjugation_galois();

void  test_single_step_rotation();
void  test_multi_step_rotation();

int main() {
  std::cout << "[CKKS] Running tests…\n";

  test_rns_and_ntt_roundtrip();
  std::cout << "[CKKS] All ntt tests passed.\n";
  test_paramgen();
  std::cout << "[CKKS] All paramgen tests passed.\n";
  test_modulus_chain();
  std::cout << "[CKKS] All params tests passed.\n";
  test_poly_add_sub_scalar();
  test_ntt_roundtrip_all_moduli();
  test_ntt_convolution();

  std::cout << "[CKKS] All poly tests passed.\n";
  test_ckks_params();
  std::cout << "[CKKS] All ckks params tests passed.\n";
  test_plaintext_ciphertext_basic();
  std::cout << "[CKKS] All plaintext & ciphertext tests passed.\n";
  test_encoder_basic_small_N();
  test_encoder_random_full_slots();
  test_encoder_multiple_levels();
  test_encoder_edge_values();

  test_secret_key_ternary();
  test_secret_key_deterministic();
  test_public_key_relation();
  test_public_key_structure();

  test_small_vector();
  test_random_vector();
  test_multi_scale();
  test_multiple_rounds();

  test_eval_add();
  test_eval_sub();
  test_eval_neg();
  test_eval_add_plain();

  test_multiply_raw();
  test_multiply_relinearize();

  test_rescale_metadata();
  test_rescale_after_mul();

  test_conjugation_galois();

  test_single_step_rotation();
  test_multi_step_rotation();

  std::cout << "[CKKS] All tests passed.\n";
  return 0;
}
