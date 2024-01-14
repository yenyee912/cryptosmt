#ifdef _MSC_VER
#define EXPORT_SYMBOL __declspec(dllexport)
#else
#define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C"
{
#endif

  EXPORT_SYMBOL long double abct_prob(uint32_t d_i, uint32_t d_ip, uint32_t d_o, uint32_t d_op);

#ifdef __cplusplus
}
#endif