/* V01 dynamic-reproduction build-failure fixture.
 *
 * Intentionally ill-formed so a controlled build fails. A build failure must
 * stay undecided and must never be treated as a safety refutation.
 */

int zscope_dynamic_repro_broken(int value)
{
    return value + undeclared_marker_symbol( /* ZSCOPE_CANDIDATE_SITE */
}
