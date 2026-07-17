/**
 * @file build_tree.h
 *
 * @brief This file transforms a linear pairwise comparison of all elements in a
 * vector into a log-tree structure.   
 *
 */

template<typename T>
struct IteratorRange
{
  using iterator = T;
  using value_type = typename std::iterator_traits<T>::value_type;
  using reference = typename std::iterator_traits<T>::reference;

  IteratorRange() :
    b{},
    e{} {}

  IteratorRange(iterator begin, iterator end) :
    b{begin},
    e{end} {}

  bool empty() const { return b == e; }
  size_t size() const { return e - b; }

  reference front() { assert(!empty()); return *b; }
  reference back() { assert(!empty()); return *std::prev(e); }
  reference operator [] (ptrdiff_t idx) const { return b[idx]; }

  iterator b, e;
};

template<typename T>
T begin(IteratorRange<T> const &r)
{
  return r.b;
}

template<typename T>
T end(IteratorRange<T> const &r)
{
  return r.e;
}

template<typename Range, typename Func>
typename Range::iterator combine_pairs(Range &range, Func &&func)
{
  using std::begin;
  using std::end;

  auto first = begin(range);
  auto last = end(range);
  if(first == last)
    return last;

  auto insert_pos = first;
  auto second = std::next(first);
  while(second != last)
  {
    *insert_pos = func(*first, *second);
    ++insert_pos;

    if(++second != last)
      ++second;

    std::advance(first, 2);
  }

  if(first != last)
  {
    *insert_pos = *first;
    ++insert_pos;
  }

  return insert_pos;
}

template<typename Range, typename Func>
typename Range::value_type& build_tree(Range &range, Func &&func)
{
  using ValueType = typename Range::value_type;
  using ItRange = IteratorRange<typename Range::iterator>;

  using std::begin;
  using std::end;

  if(range.empty())
    throw std::runtime_error{"build_tree(): range is empty"};

  ItRange sub_range{begin(range), end(range)};
  auto second = std::next(begin(range));
  int level = 0;
  while(second != sub_range.e)
  {
    sub_range.e = combine_pairs(sub_range, [&](ValueType const &a, ValueType const &b)
    {
      return func(a, b, level);
    });

    level++;
  }

  return *sub_range.b;
}
